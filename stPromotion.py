# This is provided as-is, and you should run it at your own risk.
# This is provided in order to provide usage examples and Axway cannot guarantee it is
# fit for production,
# or provide ongoing support for it.
# Author: Hristina Stoykova
import warnings
import copy
import os
import hvac
from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata
import dotenv
from requests_toolbelt.utils import dump
from func import *


# Load environment variables
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)

# Suppress specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Hashi
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")
vault = 'SecureTransport'
tier = 'non-production'
# Hashi Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
    verify=False
)

# Authenticate with ST
# Clear log file so only current run is visible
open('Logs/master.log', 'w').close()
s_source, source_ST = Authenticate(os.environ.get("ST_SOURCE", "ST_NON_PROD"))
s_source.verify = False
s_source.headers.update({'Accept': 'application/json'})
s_target, target_ST = Authenticate(os.environ.get("ST_TARGET", "ST_PROD"))
s_target.verify = False
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})

# SETTINGS
accountsToMigrate = [os.environ.get("ACCOUNT_NAME", "hrisy")]



### IMPORT TO TARGET ST
## MIGRATE TEMPLATE ROUTES
res_sourceVersion = s_source.get(source_ST + 'version')
res_targetVersion = s_target.get(target_ST + 'version')
targetInstalledPlugins = []
for s in res_targetVersion.json().get('plugins', []):
    targetInstalledPlugins.append(s['name'])
resource = "routes/"
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})
migrate_route_templates(s_source, source_ST, s_target, target_ST, resource)

### HANDLE ACCOUNTS MIGRATION

resource = 'accountSetup/'
for i in accountsToMigrate:
    res = s_source.get(source_ST + resource + i)
    accountSetup = res.json()
    # ACCOUNT SETTINGS
    accountSetup['accountSetup']['account']['disabled'] = True
    # CERTIFICATE SETTINGS
    certificates = copy.deepcopy(accountSetup['accountSetup']['certificates'])
    # Summary counters
    src_certs  = len(certificates['private']) + len(certificates.get('partner', []))
    src_sites  = len(accountSetup['accountSetup']['sites'])
    src_routes = len(accountSetup['accountSetup']['routes'])
    src_subs   = len(accountSetup['accountSetup']['subscriptions'])
    created_certs = 0
    created_sites = 0
    created_routes = 0
    created_subs = 0
    # ROUTES
    compositeRoutes = copy.deepcopy(accountSetup['accountSetup']['routes'])
    for route in accountSetup['accountSetup']['routes']:
        route['subscriptions'].clear()
        for step in route['steps']:
            if step['type'] == "ExecuteRoute":
                route['steps'].remove(step)
    # SUBSCRIPTIONS
    subscriptions = copy.deepcopy(accountSetup['accountSetup']['subscriptions'])

    # TRANSFER SITES
    sites = copy.deepcopy(accountSetup['accountSetup']['sites'])
    accountSetup['accountSetup']['sites'].clear()
    accountSetup['accountSetup']['subscriptions'].clear()
    fields = []

    resource = 'certificates/'
    del s_source.headers['content-type']
    if accountSetup['accountSetup']['certificates']['partner']:
        for cert in accountSetup['accountSetup']['certificates']['partner'][:]:
            cert_already_exists = False
            if cert.get('alias'):
                params = {'account': i, 'type': cert['type'], 'usage': cert.get('usage', 'partner'), 'name': cert['alias']}
                checkIfExists = s_target.get(target_ST + resource, params=params)
                checkIfExistsResult = checkIfExists.json()
                cert_already_exists = bool(checkIfExistsResult['result'])
            if not cert_already_exists:
                s_source.headers.update({'Accept': 'multipart/mixed'})
                export_params = {}
                if cert.get('type') == 'ssh':
                    export_params['exportSSHPublicKey'] = 'true'
                cert_res = s_source.get(source_ST + "certificates/" + cert['keyName'], params=export_params)
                if cert_res.ok:
                    json_info, cert_binary, rf = parse_certificates(cert_res)
                else:
                    print(cert_res.text)
                # Use alias if available, otherwise generate from subject or keyName
                effective_alias = cert.get('alias') or json_info.get('subject', cert['keyName'])
                keyname = cert['keyName'] = effective_alias
                # Rebuild the RequestField with the correct name so it matches keyName in the JSON
                rf = RequestField(name=effective_alias, data=cert_binary,
                                  headers={'keyname': effective_alias, 'encoded': 'false'})
                rf.make_multipart(content_disposition='attachment', content_type='application/octet-stream')
                cert['generate'] = False
                if 'caPassword' in cert:
                    del cert['caPassword']
                cert.pop('certificatePassword', None)
                fields.append(rf)
                created_certs += 1
            else:
                accountSetup['accountSetup']['certificates']['partner'].remove(cert)
    if accountSetup['accountSetup']['certificates']['private']:
        for cert in accountSetup['accountSetup']['certificates']['private'][:]:
            params = {'account': i, 'usage': 'private', 'name': cert['alias']}
            checkIfExists = s_target.get(target_ST + resource, params=params)
            checkIfExistsResult = checkIfExists.json()
            if not checkIfExistsResult['result']:
                s_source.headers.update({'Accept': 'multipart/mixed'})
                params = {'password': 'password', 'exportPrivateKey': 'true'}
                cert_res = s_source.get(source_ST + "certificates/" + cert['keyName'], params=params)
                if cert_res.ok:
                    json_info, cert_binary, rf = parse_certificates(cert_res)
                else:
                    print(cert_res.text)
                keyname = cert['keyName'] = cert['alias']
                cert['generate'] = False
                cert['certificatePassword'] = params['password']
                if cert['type'] == 'ssh':
                    cert['type'] = 'x509'
                fields.append(rf)
                created_certs += 1
            else:
                accountSetup['accountSetup']['certificates']['private'].remove(cert)
    for subs in accountSetup['accountSetup']['subscriptions']:
        for transferConf in subs['transferConfigurations']:
            if 'id' in transferConf:
                transferConf.pop('id')

    # IMPORT ACCOUNT, SITES, COMPOSITE ROUTES, AND NON AR SUBSCRIPTIONS
    # Strip pesitId before building the body — ST rejects accounts with pesitId but no PeSIT site.
    # It will be patched back after the pesit site is created.
    pesitId = accountSetup['accountSetup']['account'].pop('pesitId', None)

    # Build the multipart body AFTER pesitId is removed
    files = {"accountSetup": (json.dumps(accountSetup), "application/json")}
    for name, (contents, mimetype) in files.items():
        rf = RequestField(name=name, data=contents)
        rf.make_multipart(content_disposition='attachment', content_type=mimetype)
        fields.append(rf)
    post_body, content_type = encode_multipart_formdata(fields)
    content_type = ''.join(('multipart/mixed',) + content_type.partition(';')[1:])

    resource = 'accountSetup/'
    # Reset headers after cert multipart upload before checking account existence
    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    account_exists = s_target.get(target_ST + 'accounts/' + i)
    logging.info(f"Account existence check for '{i}': status={account_exists.status_code}")
    if account_exists.ok:
        logging.info(f"Account '{i}' already exists on target — skipping accountSetup POST")
    elif not (accountSetup['accountSetup']['certificates']['private'] or accountSetup['accountSetup']['certificates'][
        'partner']):
        response = s_target.post(target_ST + resource, json=accountSetup)
        logging.info(f"accountSetup JSON status: {response.status_code}, Message: {response.text}")
        data = dump.dump_all(response)
        logging.debug(data.decode(errors='ignore'))

    else:
        s_target.headers.update({'Content-Type': content_type})
        s_target.headers.update({'Accept': '*/*'})
        resource = 'accountSetup/'
        response = s_target.post(target_ST + resource, data=post_body)
        data = dump.dump_all(response)
        logging.info(f"accountSetup status: {response.status_code}, Message: {response.text}")
        logging.debug(data.decode(errors='ignore'))

    s_target.headers.update({'Accept': 'application/json'})
    s_target.headers.update({'Content-Type': 'application/json'})
    resource = 'accountSetup/'
    res_accountSetup = s_target.get(target_ST + resource + i)
    accountSetupTaget = res_accountSetup.json()
    targetSites = []
    for site_target in accountSetupTaget['accountSetup']['sites']:
        targetSites.append(site_target['name'])
    # Create pesit site first — account with pesitId requires a PeSIT site to exist
    sites.sort(key=lambda s: 0 if s.get('type') == 'pesit' else 1)
    for site in sites:
        is_plugin_site = site['type'] == 'ExternalPersistedCustomSite'
        plugin_available = site['protocol'] in targetInstalledPlugins
        if site['name'] not in targetSites and (not is_plugin_site or plugin_available):
            path = f'accounts/{i}/sites/{tier}/{site["name"]}'
            read_response = read_secret_version(client, vault, path)
            metadata = read_response['data']['metadata'].get('custom_metadata', {})
            data = read_response['data'].get('data', {})
            if site['type'] == 'ExternalPersistedCustomSite':
                update_custom_properties(site, metadata, data)
                # Strip top-level site fields that may have leaked into customProperties
                for leaked_key in ('type', 'protocol', 'siteName', 'name', 'account', 'id'):
                    site['customProperties'].pop(leaked_key, None)
                # Default empty folder paths to '/' (API requires 1-255 chars)
                for folder_key in [k for k in site['customProperties'] if k.endswith(('DownloadFolder', 'UploadFolder', 'downloadFolder', 'uploadFolder'))]:
                    if site['customProperties'][folder_key] == '':
                        site['customProperties'][folder_key] = '/'
                # For azure-file SAS sites, the API still requires AccountName/Key/EndpointSuffix
                # to be present and non-empty even though SAS auth doesn't use them.
                if site.get('protocol') == 'azure-file' and site['customProperties'].get('azurefileConnectionType') == 'sas':
                    for sas_only_field in ('azurefileAccountName', 'azurefileAccountKey', 'azurefileEndpointSuffix'):
                        if not site['customProperties'].get(sas_only_field):
                            site['customProperties'][sas_only_field] = 'N/A'
            else:
                update_site_properties(site, metadata, data)
            # Remap all certificate reference fields from source IDs to target IDs
            cert_fields = [k for k in site if 'ertificate' in k and site[k] and isinstance(site[k], str)]
            all_source_certs = certificates['private'] + certificates.get('partner', [])
            all_target_certs = (accountSetupTaget['accountSetup']['certificates']['private'] +
                                accountSetupTaget['accountSetup']['certificates'].get('partner', []))
            original_cert_ids = {}
            for cert_field in cert_fields:
                source_id = site[cert_field]
                original_cert_ids[cert_field] = source_id
                logging.info(f"Remapping cert field '{cert_field}' source_id='{source_id}'")
                # Resolve metadata from the source cert snapshot
                source_alias = None
                source_fingerprint = None
                source_usage = None
                source_type = None
                source_subject = None
                found_in_snapshot = False
                for c in all_source_certs:
                    if c['keyName'] == source_id or c.get('alias') == source_id:
                        source_alias = c.get('alias')
                        source_fingerprint = c.get('fingerprint')
                        source_usage = c.get('usage')
                        source_type = c.get('type')
                        source_subject = c.get('subject')
                        found_in_snapshot = True
                        logging.info(f"  Found in snapshot: alias={source_alias} subject={source_subject} usage={source_usage} type={source_type}")
                        break
                # If not found in snapshot at all, or found but missing key identifiers, query source directly
                if not found_in_snapshot or (not source_subject and not source_alias):
                    s_source.headers.update({'Accept': 'application/json'})
                    src_lookup = s_source.get(source_ST + 'certificates/' + source_id)
                    if src_lookup.ok:
                        src_cert = src_lookup.json()
                        source_alias = source_alias or src_cert.get('alias') or src_cert.get('name')
                        source_fingerprint = source_fingerprint or src_cert.get('fingerprint')
                        source_usage = source_usage or src_cert.get('usage')
                        source_type = source_type or src_cert.get('type')
                        source_subject = source_subject or src_cert.get('subject')
                        logging.info(f"  Enriched via source API: alias={source_alias} subject={source_subject} usage={source_usage} type={source_type}")
                if not source_subject and not source_alias:
                    logging.warning(f"Cannot resolve cert metadata for field '{cert_field}' source_id='{source_id}'")
                    continue

                remapped = False

                # Step 1: try the source ID directly on the target (cert may have same ID)
                s_target.headers.update({'Accept': 'application/json'})
                direct = s_target.get(target_ST + 'certificates/' + source_id)
                if direct.ok:
                    site[cert_field] = source_id
                    remapped = True
                    logging.info(f"  Remapped via direct ID lookup on target")

                # Step 2: match in target accountSetup snapshot
                if not remapped:
                    for c_target in all_target_certs:
                        alias_match = source_alias and c_target.get('alias') == source_alias
                        subject_match = (source_subject and source_usage and
                                         c_target.get('subject') == source_subject and
                                         c_target.get('usage') == source_usage)
                        if alias_match or subject_match:
                            site[cert_field] = c_target.get('keyName') or c_target.get('id')
                            remapped = True
                            logging.info(f"  Remapped via target snapshot")
                            break

                # Step 3: search target API by subject/alias/usage/type
                if not remapped:
                    search_attempts = []
                    if source_subject and source_usage and source_type:
                        search_attempts.append({'account': i, 'subject': source_subject, 'usage': source_usage, 'type': source_type})
                        search_attempts.append({'subject': source_subject, 'usage': source_usage, 'type': source_type})
                    if source_subject and source_usage:
                        search_attempts.append({'account': i, 'subject': source_subject, 'usage': source_usage})
                        search_attempts.append({'subject': source_subject, 'usage': source_usage})
                    if source_alias and source_usage:
                        search_attempts.append({'account': i, 'name': source_alias, 'usage': source_usage})
                        search_attempts.append({'name': source_alias, 'usage': source_usage})
                    if source_alias:
                        search_attempts.append({'account': i, 'name': source_alias})
                        search_attempts.append({'name': source_alias})
                    for params in search_attempts:
                        fallback = s_target.get(target_ST + 'certificates/', params=params)
                        logging.info(f"  API search params={params} -> status={fallback.status_code} count={fallback.json().get('resultSet', {}).get('totalCount') if fallback.ok else 'err'}")
                        if fallback.ok and fallback.json().get('result'):
                            cert_result = fallback.json()['result'][0]
                            site[cert_field] = cert_result.get('keyName') or cert_result.get('id')
                            remapped = True
                            logging.info(f"  Remapped via API search: {params}")
                            break

                # Step 4: export from source (multipart) and import to target
                if not remapped:
                    try:
                        s_source.headers.update({'Accept': 'multipart/mixed'})
                        export_params = {}
                        if source_type == 'ssh':
                            export_params['exportSSHPublicKey'] = 'true'
                        elif source_usage == 'private':
                            export_params = {'password': 'password', 'exportPrivateKey': 'true'}
                        src_export = s_source.get(source_ST + 'certificates/' + source_id, params=export_params)
                        if src_export.ok:
                            cert_json, cert_binary, cert_rf = parse_certificates(src_export)
                            # Build the JSON metadata for import — only include supported fields
                            cert_json['account'] = i
                            for unsupported in ('id', 'fingerprint', 'validationStatus', 'metadata',
                                                'creationTime', 'expirationTime', 'additionalAttributes',
                                                'generate', 'signerKeyId', 'pgpSubKeys', 'exportPrivateKey',
                                                'exportSSHPublicKey', 'caPassword', 'password',
                                                'keySize', 'validityPeriod', 'keyAlgorithm', 'signAlgorithm'):
                                cert_json.pop(unsupported, None)
                            if source_usage == 'private' and export_params.get('password'):
                                cert_json['certificatePassword'] = export_params['password']
                            if source_usage != 'private':
                                cert_json.pop('certificatePassword', None)
                            # SSH login certs can be overwritten by fingerprint
                            if source_type == 'ssh':
                                cert_json['overwrite'] = True
                            # Build multipart body: JSON metadata + cert binary
                            import_fields = [cert_rf]
                            cert_setup_rf = RequestField(
                                name='certificate',
                                data=json.dumps(cert_json)
                            )
                            cert_setup_rf.make_multipart(
                                content_disposition='attachment',
                                content_type='application/json'
                            )
                            import_fields.append(cert_setup_rf)
                            body, ct = encode_multipart_formdata(import_fields)
                            ct = ''.join(('multipart/mixed',) + ct.partition(';')[1:])
                            s_target.headers.update({'Content-Type': ct, 'Accept': '*/*'})
                            import_resp = s_target.post(target_ST + 'certificates/', data=body)
                            s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                            logging.info(f"  Multipart import status={import_resp.status_code} body={import_resp.text[:300] if import_resp.text else ''}")
                            if import_resp.ok or import_resp.status_code == 201:
                                # Find the newly uploaded cert on the target
                                for search_params in (
                                    {'account': i, 'subject': source_subject, 'usage': source_usage, 'type': source_type},
                                    {'account': i, 'subject': source_subject, 'usage': source_usage},
                                    {'account': i, 'subject': source_subject},
                                ):
                                    chk = s_target.get(target_ST + 'certificates/', params=search_params)
                                    if chk.ok and chk.json().get('result'):
                                        cert_result = chk.json()['result'][0]
                                        site[cert_field] = cert_result.get('keyName') or cert_result.get('id')
                                        remapped = True
                                        created_certs += 1
                                        logging.info(f"  Imported cert via multipart for field '{cert_field}' (subject='{source_subject}')")
                                        break
                                if not remapped:
                                    logging.warning(f"  Cert imported but could not find it on target by subject")
                            else:
                                logging.warning(f"  Multipart import failed for field '{cert_field}': {import_resp.text[:300] if import_resp.text else ''}")
                        else:
                            logging.warning(f"  Could not export cert from source: {src_export.status_code}")
                        s_source.headers.update({'Accept': 'application/json'})
                    except Exception as e:
                        logging.warning(f"  Exception during cert export/import for '{cert_field}': {e}")
                        s_source.headers.update({'Accept': 'application/json'})
                        s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})

                if not remapped:
                    logging.warning(f"Could not remap cert field '{cert_field}' source_id='{source_id}' (alias='{source_alias}', subject='{source_subject}', usage='{source_usage}') — setting to null to allow site creation")
                    site[cert_field] = None
            # Track cert fields that were nulled for later patching
            # original_cert_ids was populated during the remapping loop above
            nulled_cert_fields = {}
            for cert_field in cert_fields:
                if site.get(cert_field) is None and cert_field in original_cert_ids:
                    nulled_cert_fields[cert_field] = original_cert_ids[cert_field]
            site.pop('siteName', None)
            site.pop('ssh_username', None)
            resource = 'sites/'
            s_target.headers.update({'Accept': 'application/json'})
            s_target.headers.update({'Content-Type': 'application/json'})
            response_s = s_target.post(target_ST + resource, json=site)
            if response_s.ok:
                created_sites += 1
                logging.info(f"site create status: {response_s.status_code}, Message: {response_s.text}")
                # Try to patch back any nulled cert fields now that the site exists
                if nulled_cert_fields:
                    # Refresh the target cert list
                    res_acct_refresh = s_target.get(target_ST + 'accountSetup/' + i)
                    if res_acct_refresh.ok:
                        refreshed_certs = (res_acct_refresh.json()['accountSetup']['certificates'].get('private', []) +
                                           res_acct_refresh.json()['accountSetup']['certificates'].get('partner', []))
                    else:
                        refreshed_certs = []
                    site_id = response_s.headers.get('Location', '').rsplit('/', 1)[-1]
                    for nf, orig_src_id in nulled_cert_fields.items():
                        # Try to find the cert on target now (it may have been uploaded via accountSetup)
                        s_source.headers.update({'Accept': 'application/json'})
                        src_cert_info = s_source.get(source_ST + 'certificates/' + orig_src_id)
                        if src_cert_info.ok:
                            sc = src_cert_info.json()
                            sc_subject = sc.get('subject')
                            sc_usage = sc.get('usage')
                            sc_type = sc.get('type')
                            target_cert_id = None
                            # Check refreshed snapshot
                            for ct in refreshed_certs:
                                if sc_subject and ct.get('subject') == sc_subject:
                                    target_cert_id = ct.get('keyName') or ct.get('id')
                                    break
                            # Check via API
                            if not target_cert_id and sc_subject:
                                for sp in (
                                    {'account': i, 'subject': sc_subject, 'usage': sc_usage, 'type': sc_type},
                                    {'account': i, 'subject': sc_subject},
                                    {'subject': sc_subject},
                                ):
                                    chk = s_target.get(target_ST + 'certificates/', params=sp)
                                    if chk.ok and chk.json().get('result'):
                                        target_cert_id = chk.json()['result'][0].get('keyName') or chk.json()['result'][0].get('id')
                                        break
                            if target_cert_id and site_id:
                                patch = [{"op": "replace", "path": f"/{nf}", "value": target_cert_id}]
                                s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                                pr = s_target.patch(target_ST + 'sites/' + site_id, json=patch)
                                if pr.ok:
                                    logging.info(f"  Patched '{nf}' on site '{site['name']}' with cert id '{target_cert_id}'")
                                else:
                                    logging.warning(f"  Failed to patch '{nf}' on site '{site['name']}': {pr.text[:200]}")
                            else:
                                logging.warning(f"  Could not find cert to patch '{nf}' on site '{site['name']}' (source_id='{orig_src_id}')")
                # Patch pesitId back onto the account now that the pesit site exists
                if site.get('type') == 'pesit' and pesitId:
                    patch_payload = [{"op": "replace", "path": "/pesitId", "value": pesitId}]
                    s_target.headers.update({'Accept': 'application/json'})
                    s_target.headers.update({'Content-Type': 'application/json'})
                    patch_resp = s_target.patch(target_ST + 'accounts/' + i, json=patch_payload)
                    if patch_resp.ok:
                        logging.info(f"Patched pesitId '{pesitId}' back onto account '{i}'")
                    else:
                        logging.warning(f"Failed to patch pesitId back: {patch_resp.text}")
            else:
                print(response_s.text)
                print(site)

    # UPDATE COMPOSITE ROUTES
    for c_route in compositeRoutes:
        resource = 'routes/'
        s_target.headers.update({'Content-Type': 'application/json'})
        s_target.headers.update({'Accept': 'application/json'})
        getRouteID = s_target.get(target_ST + resource, params=dict(fields='id,steps', account=i, type='COMPOSITE',
                                                                    name=c_route['name']))
        executeRoute = False
        if getRouteID.json()['result'] and getRouteID.json()['result'][0]['steps'] and  'executeRoute' in getRouteID.json()['result'][0]['steps'][0]:
            executeRoute = True

        new_c_route_id = getRouteID.json()['result'][0]['id']

        # ASSIGN SUBSCRIPTIONS
        if c_route['subscriptions']:
            newSubscriptions = []
            for sub in c_route['subscriptions']:
                resource = 'subscriptions/'
                s_source.headers.update({'Accept': 'application/json'})
                s_source.headers.update({'Content-Type': 'application/json'})
                result = s_source.get(source_ST + resource + sub)
                source_sub = result.json()

                checkIfExists = s_target.get(target_ST + resource, params={'account': i,
                                                                           'folder': source_sub['folder']})
                checkIfExistsResult = checkIfExists.json()
                if checkIfExistsResult['resultSet']['totalCount'] == 0:
                    for transferConf in source_sub['transferConfigurations']:
                        transferConf.pop('id')
                    # Check the application exists on the target; if not, fetch from source and create it
                    app_name = source_sub.get('application')
                    if app_name:
                        s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                        app_head = s_target.head(target_ST + 'applications/' + app_name)
                        if app_head.status_code == 404:
                            s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                            src_app_res = s_source.get(source_ST + 'applications/' + app_name)
                            if src_app_res.ok:
                                app_body = src_app_res.json()
                                app_body.pop('id', None)
                                s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                                app_create = s_target.post(target_ST + 'applications/', json=app_body)
                                if app_create.ok:
                                    logging.info(f"Created application '{app_name}' on target")
                                elif 'already exists' in app_create.text:
                                    logging.info(f"Application '{app_name}' already exists on target")
                                else:
                                    logging.warning(f"Failed to create application '{app_name}' on target: {app_create.text} — skipping subscription")
                                    continue
                            else:
                                logging.warning(f"Could not fetch application '{app_name}' from source (status={src_app_res.status_code}) — skipping subscription")
                                continue
                    s_target.headers.update({'Accept': 'application/json'})
                    s_target.headers.update({'Content-Type': 'application/json'})
                    create = s_target.post(target_ST + resource, json=source_sub)
                    if create.ok:
                        subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
                        newSubscriptions.append(subscriptionID)
                        created_subs += 1
                    else:
                        logging.warning(f"Subscription create status: {create.status_code}, Message: {create.text}")
                else:
                    subscriptionID = checkIfExistsResult['result'][0]['id']
                    newSubscriptions.append(subscriptionID)

                payload = [
                    {
                        "op": "replace",
                        "path": "/subscriptions",
                        "value": newSubscriptions
                    }
                ]
                resource = 'routes/'
                s_target.headers.update({'Content-Type': 'application/json'})
                s_target.headers.update({'Accept': 'application/json'})

                response = s_target.patch(target_ST + resource + new_c_route_id, json=payload)
                logging.info(f"subscription update status {response.status_code}; Message: {response.text}")
        if c_route['steps'] and c_route['steps'][0]['type'] == 'ExecuteRoute' and not executeRoute:
            s_source.headers.update({'Accept': 'application/json'})
            s_source.headers.update({'Content-Type': 'application/json'})
            resp = s_source.get(c_route['steps'][0]['metadata']['links']['executeRoute'])
            simpleRouteName = resp.json()['name']
            s_target.headers.update({'Content-Type': 'application/json'})
            s_target.headers.update({'Accept': 'application/json'})
            checkIfSimpleRouteExists = s_target.get(target_ST + resource, params=dict(type='SIMPLE',
                                                                                      name=simpleRouteName))
            if checkIfSimpleRouteExists.json()['resultSet']['totalCount'] > 0:
                simpleRouteID = checkIfSimpleRouteExists.json()['result'][0]['id']
            else:
                for step in c_route['steps']:
                    metadataURI = step['metadata']['links']['executeRoute']
                    s_source.headers.update({'Accept': 'application/json'})
                    s_source.headers.update({'Content-Type': 'application/json'})
                    result = s_source.get(metadataURI)
                    if not result.ok:
                        print(result.text)
                    if result.ok:
                        data = result.json()
                        data.pop('id')

                        for r_step in data['steps']:
                            if 'precedingStep' in r_step:
                                r_step.pop('precedingStep')
                        s_target.headers.update({'Content-Type': 'application/json'})
                        s_target.headers.update({'Accept': 'application/json'})

                        create = s_target.post(target_ST + resource, json=data)
                        if not create.ok:
                            print(create.text)
                        else:
                            created_routes += 1
                        simpleRouteID = create.headers['Location'].rsplit('/', 1)[-1]
            data = c_route['steps'][0]
            data.pop('id')
            data.pop('metadata')
            data['executeRoute'] = simpleRouteID
            payload = [
                {
                    "op": "replace",
                    "path": "/steps",
                    "value": [data]
                }
            ]
            s_target.headers.update({'Accept': 'application/json'})
            s_target.headers.update({'Content-Type': 'application/json'})
            response = s_target.patch(target_ST + resource + new_c_route_id, json=payload)
            logging.info(f"subscription update status {response.status_code}; Message: {response.text}")
    resource = 'subscriptions/'
    targetSites = []
    for sub_target in accountSetupTaget['accountSetup']['subscriptions']:
        targetSites.append(sub_target['folder'])
    for subscription in subscriptions[:]:
        if subscription['folder'] not in targetSites:
            subscription.pop('id')
            for tc in subscription['transferConfigurations']:
                tc.pop('id')
            # Ensure the application exists on the target; if not, fetch from source and create it
            app_name = subscription.get('application')
            if app_name:
                # Use HEAD /applications/{name} for reliable existence check
                s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                app_head = s_target.head(target_ST + 'applications/' + app_name)
                if app_head.status_code == 404:
                    # App doesn't exist — fetch from source and create
                    s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                    src_app_res = s_source.get(source_ST + 'applications/' + app_name)
                    if src_app_res.ok:
                        app_body = src_app_res.json()
                        app_body.pop('id', None)
                        s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                        app_create = s_target.post(target_ST + 'applications/', json=app_body)
                        if app_create.ok:
                            logging.info(f"Created application '{app_name}' on target")
                        elif 'already exists' in app_create.text:
                            logging.info(f"Application '{app_name}' already exists on target")
                        else:
                            logging.warning(f"Failed to create application '{app_name}' on target: {app_create.text} — skipping subscription for folder '{subscription.get('folder')}'")
                            continue
                    else:
                        logging.warning(f"Could not fetch application '{app_name}' from source (status={src_app_res.status_code}) — skipping subscription for folder '{subscription.get('folder')}'")
                        continue
            # Check that the referenced site exists on the target before creating the subscription
            site_name = subscription.get('siteName') or subscription.get('transferSiteName')
            if site_name:
                site_check = s_target.get(target_ST + 'sites/', params={'account': i, 'name': site_name})
                if not site_check.ok or site_check.json().get('resultSet', {}).get('totalCount', 0) == 0:
                    logging.warning(f"Skipping subscription for folder '{subscription.get('folder')}': site '{site_name}' not found on target")
                    continue
            response = s_target.post(target_ST + resource, json=subscription)
            if response.ok:
                created_subs += 1
                logging.info(f"Standalone subscription created for folder '{subscription.get('folder')}': {response.status_code}")
            elif response.status_code == 404 and 'Application with name' in response.text:
                # Extract app name from error and try to create it
                import re as _re
                match = _re.search(r'Application with name (\S+) not found', response.text)
                if match:
                    missing_app = match.group(1)
                    s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                    src_app_res = s_source.get(source_ST + 'applications/' + missing_app)
                    if src_app_res.ok:
                        app_body = src_app_res.json()
                        app_body.pop('id', None)
                        s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                        app_create = s_target.post(target_ST + 'applications/', json=app_body)
                        if app_create.ok or 'already exists' in app_create.text:
                            logging.info(f"Application '{missing_app}' available on target, retrying subscription")
                            retry = s_target.post(target_ST + resource, json=subscription)
                            if retry.ok:
                                created_subs += 1
                                logging.info(f"Standalone subscription created for folder '{subscription.get('folder')}' on retry: {retry.status_code}")
                            else:
                                logging.warning(f"Standalone subscription retry failed for folder '{subscription.get('folder')}': {retry.status_code}, {retry.text}")
                        else:
                            logging.warning(f"Failed to create application '{missing_app}': {app_create.text}")
                    else:
                        logging.warning(f"Could not fetch application '{missing_app}' from source")
                else:
                    logging.warning(f"Standalone subscription failed for folder '{subscription.get('folder')}': {response.status_code}, {response.text}")
            else:
                logging.warning(f"Standalone subscription failed for folder '{subscription.get('folder')}': {response.status_code}, {response.text}")

    # ── Transfer Profiles ──────────────────────────────────────────────────────
    resource = 'transferProfiles/'
    s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    src_profiles_res = s_source.get(source_ST + resource, params={'account': i, 'limit': 200})
    src_profiles = src_profiles_res.json().get('result', []) if src_profiles_res.ok else []
    src_tp = len(src_profiles)
    created_tp = 0

    # Get existing transfer profiles on target
    tgt_profiles_res = s_target.get(target_ST + resource, params={'account': i, 'limit': 200})
    tgt_profile_names = set()
    if tgt_profiles_res.ok:
        for tp in tgt_profiles_res.json().get('result', []):
            tgt_profile_names.add(tp.get('name'))

    for profile in src_profiles:
        if profile.get('name') in tgt_profile_names:
            logging.info(f"Transfer profile '{profile.get('name')}' already exists on target — skipping")
            continue
        # Clean up read-only / server-generated fields
        profile.pop('id', None)
        profile.pop('metadata', None)
        profile.pop('additionalAttributes', None)
        tp_resp = s_target.post(target_ST + resource, json=profile)
        if tp_resp.ok:
            created_tp += 1
            logging.info(f"Transfer profile '{profile.get('name')}' created on target")
        else:
            logging.warning(f"Failed to create transfer profile '{profile.get('name')}': {tp_resp.status_code}, {tp_resp.text}")

    # ── Migration summary ──────────────────────────────────────────────────────
    summary = (
        f"\n{'─' * 54}\n"
        f"  Migration summary for account: {i}\n"
        f"{'─' * 54}\n"
        f"  {'Item':<20} {'Source':>8}   {'Created on target':>17}\n"
        f"  {'─' * 48}\n"
        f"  {'Certificates':<20} {src_certs:>8}   {created_certs:>17}\n"
        f"  {'Transfer sites':<20} {src_sites:>8}   {created_sites:>17}\n"
        f"  {'Routes':<20} {src_routes:>8}   {created_routes:>17}\n"
        f"  {'Subscriptions':<20} {src_subs:>8}   {created_subs:>17}\n"
        f"  {'Transfer profiles':<20} {src_tp:>8}   {created_tp:>17}\n"
        f"{'─' * 54}"
    )
    print(summary)
    logging.info(summary)
