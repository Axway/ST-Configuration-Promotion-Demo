import sys
import warnings
import dotenv
from func import *

import hvac

_account = os.environ.get("ACCOUNT_NAME", "hrisy")
_site = os.environ.get("SITE_NAME", "SMB")
siteToMigrate = [{_account: _site}]

# SETTINGS
warnings.filterwarnings("ignore", category=DeprecationWarning)
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")

# Clear log file so only current run is visible
open('Logs/master.log', 'w').close()

# Authenticate with ST
s_source, source_ST = Authenticate(os.environ.get("ST_SOURCE", "ST_NON_PROD"))
s_source.verify = False
s_source.headers.update({'Accept': 'application/json'})
s_target, target_ST = Authenticate(os.environ.get("ST_TARGET", "ST_PROD"))
s_target.verify = False
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})

# VARS
vault = 'SecureTransport'
tier = 'production'
# Hashi Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
    verify=False
)

has_errors = False

# EXPORT FROM SOURCE ST
resource = "sites/"
for sites in siteToMigrate:
    for k, v in sites.items():
        params = {'account': k, 'name': v}
        res = s_source.get(source_ST + resource, params=params)
        if not res.ok or not res.json().get('result'):
            logging.error(f"Site '{v}' not found on source for account '{k}'")
            print(f"ERROR: Site '{v}' not found on source for account '{k}'")
            has_errors = True
            continue
        site = res.json()['result'][0]
        path = f'accounts/{k}/sites/{tier}/{v}'
        read_response = read_secret_version(client, vault, path)
        metadata = read_response['data']['metadata'].get('custom_metadata', {})
        data = read_response['data'].get('data', {})
        if site['type'] == 'ExternalPersistedCustomSite':
            update_custom_properties(site, metadata, data)
            # Strip top-level site fields that may have leaked into customProperties
            for leaked_key in ('type', 'protocol', 'siteName', 'name', 'account', 'id'):
                site['customProperties'].pop(leaked_key, None)
            # Default empty folder paths to '/' (API requires 1-255 chars)
            for folder_key in [fk for fk in site['customProperties']
                               if fk.endswith(('DownloadFolder', 'UploadFolder', 'downloadFolder', 'uploadFolder'))]:
                if site['customProperties'][folder_key] == '':
                    site['customProperties'][folder_key] = '/'
            # For azure-file SAS sites, the API requires AccountName/Key/EndpointSuffix even for SAS
            if site.get('protocol') == 'azure-file' and site['customProperties'].get('azurefileConnectionType') == 'sas':
                for sas_field in ('azurefileAccountName', 'azurefileAccountKey', 'azurefileEndpointSuffix'):
                    if not site['customProperties'].get(sas_field):
                        site['customProperties'][sas_field] = 'N/A'
        else:
            update_site_properties(site, metadata, data)

        # ── Remap certificate references from source IDs to target IDs ──────
        cert_fields = [fld for fld in site if 'ertificate' in fld and site[fld] and isinstance(site[fld], str)]
        for cert_field in cert_fields:
            source_id = site[cert_field]
            logging.info(f"Remapping cert field '{cert_field}' source_id='{source_id}'")

            # Get cert metadata from source
            source_alias = None
            source_subject = None
            source_usage = None
            source_type = None
            s_source.headers.update({'Accept': 'application/json'})
            src_lookup = s_source.get(source_ST + 'certificates/' + source_id)
            if src_lookup.ok:
                src_cert = src_lookup.json()
                source_alias = src_cert.get('alias') or src_cert.get('name')
                source_subject = src_cert.get('subject')
                source_usage = src_cert.get('usage')
                source_type = src_cert.get('type')
                logging.info(f"  Source cert: alias={source_alias} subject={source_subject} usage={source_usage} type={source_type}")
            else:
                logging.warning(f"  Could not fetch cert metadata from source for id '{source_id}'")

            if not source_subject and not source_alias:
                logging.warning(f"  Cannot resolve cert metadata for '{cert_field}' — setting to null")
                site[cert_field] = None
                continue

            remapped = False

            # Step 1: try the source ID directly on the target
            s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            direct = s_target.get(target_ST + 'certificates/' + source_id)
            if direct.ok:
                site[cert_field] = source_id
                remapped = True
                logging.info(f"  Remapped via direct ID lookup")

            # Step 2: search target API by subject/alias/usage/type
            if not remapped:
                search_attempts = []
                if source_subject and source_usage and source_type:
                    search_attempts.append({'account': k, 'subject': source_subject, 'usage': source_usage, 'type': source_type})
                    search_attempts.append({'subject': source_subject, 'usage': source_usage, 'type': source_type})
                if source_subject and source_usage:
                    search_attempts.append({'account': k, 'subject': source_subject, 'usage': source_usage})
                    search_attempts.append({'subject': source_subject, 'usage': source_usage})
                if source_alias and source_usage:
                    search_attempts.append({'account': k, 'name': source_alias, 'usage': source_usage})
                    search_attempts.append({'name': source_alias, 'usage': source_usage})
                if source_alias:
                    search_attempts.append({'account': k, 'name': source_alias})
                    search_attempts.append({'name': source_alias})
                for sp in search_attempts:
                    fallback = s_target.get(target_ST + 'certificates/', params=sp)
                    count = fallback.json().get('resultSet', {}).get('totalCount', 0) if fallback.ok else 0
                    logging.info(f"  API search params={sp} -> status={fallback.status_code} count={count}")
                    if fallback.ok and fallback.json().get('result'):
                        cert_result = fallback.json()['result'][0]
                        site[cert_field] = cert_result.get('keyName') or cert_result.get('id')
                        remapped = True
                        logging.info(f"  Remapped via API search")
                        break

            if not remapped:
                logging.warning(f"  Could not remap cert field '{cert_field}' source_id='{source_id}' — setting to null")
                site[cert_field] = None

        # ── Create or update the site on target ────────────────────────────
        site.pop('id', None)
        site.pop('metadata', None)
        site.pop('siteName', None)
        site.pop('ssh_username', None)
        site.pop('additionalAttributes', None)
        checkIfExists = s_target.get(target_ST + resource, params={'account': k, 'name': v})
        checkIfExistsResult = checkIfExists.json()
        if checkIfExistsResult['resultSet']['totalCount'] == 0:
            response = s_target.post(target_ST + resource, json=site)
            if response.ok:
                logging.info(f"Site '{v}' created: {response.status_code}")
                print(f"Site '{v}' created successfully")
            else:
                logging.error(f"Site '{v}' creation failed: {response.status_code}, {response.text}")
                print(f"ERROR: Site '{v}' creation failed: {response.text}")
                has_errors = True
        else:
            existing_id = checkIfExistsResult['result'][0]['id']
            logging.info(f"Site '{v}' already exists, updating...")
            response = s_target.put(target_ST + resource + existing_id, json=site)
            if response.ok:
                logging.info(f"Site '{v}' updated successfully")
                print(f"Site '{v}' updated successfully")
            else:
                logging.error(f"Site '{v}' update failed: {response.status_code}, {response.text}")
                print(f"ERROR: Site '{v}' update failed: {response.text}")
                has_errors = True

if has_errors:
    sys.exit(1)
