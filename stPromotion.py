# This is provided as-is, and you should run it at your own risk.
# This is provided in order to provide usage examples and Axway cannot guarantee it is fit for production,
# or provide ongoing support for it.
# Author: Hristina Stoykova


from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata
import warnings
import dotenv
from func import *
import hvac
from requests_toolbelt.utils import dump
import os
import copy
import urllib3

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
tier = 'production'
# Hashi Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
    verify=False
)

# Authenticate with ST
s_source, source_ST = Authenticate("ST_NON_PROD")
s_source.verify = False
s_source.headers.update({'Accept': 'application/json'})
s_target, target_ST = Authenticate("ST_PROD")
s_target.verify = False
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})

# SETTINGS
accountsToMigrate = ['hrisy']

### IMPORT TO TARGET ST
## MIGRATE TEMPLATE ROUTES
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
            params = {'account': i, 'type': cert['type'], 'usage': 'partner', 'name': cert['alias']}
            checkIfExists = s_target.get(target_ST + resource, params=params)
            checkIfExistsResult = checkIfExists.json()
            if not checkIfExistsResult['result']:
                s_source.headers.update({'Accept': 'multipart/mixed'})
                cert_res = s_source.get(source_ST + "certificates/" + cert['keyName'])
                if cert_res.ok:
                    json_info, cert_binary, rf = parse_certificates(cert_res)
                else:
                    print(cert_res.text)
                keyname = cert['keyName'] = cert['alias']
                cert['generate'] = False
                if 'caPassword' in cert:
                    del cert['caPassword']
                del cert['certificatePassword']

                fields.append(rf)
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
            else:
                accountSetup['accountSetup']['certificates']['private'].remove(cert)
    files = {"accountSetup": (json.dumps(accountSetup), "application/json")}
    for name, (contents, mimetype) in files.items():
        rf = RequestField(name=name, data=contents)
        rf.make_multipart(content_disposition='attachment', content_type=mimetype)
        fields.append(rf)
    post_body, content_type = encode_multipart_formdata(fields)
    content_type = ''.join(('multipart/mixed',) + content_type.partition(';')[1:])

    for subs in accountSetup['accountSetup']['subscriptions']:
        for transferConf in subs['transferConfigurations']:
            if 'id' in transferConf:
                transferConf.pop('id')

    # IMPORT ACCOUNT, SITES, COMPOSITE ROUTES, AND NON AR SUBSCRIPTIONS
    resource = 'accountSetup/'
    if not (accountSetup['accountSetup']['certificates']['private'] or accountSetup['accountSetup']['certificates'][
        'partner']):
        s_target.headers.update({'Accept': 'application/json'})
        s_target.headers.update({'Content-Type': 'application/json'})
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
    res_accountSetup = s_target.get(target_ST + resource + i)
    accountSetupTaget = res_accountSetup.json()
    targetSites = []
    for site_target in accountSetupTaget['accountSetup']['sites']:
        targetSites.append(site_target['name'])
    for site in sites:
        if site['name'] not in targetSites:
            path = f'accounts/{i}/sites/{tier}/{site["name"]}'
            read_response = read_secret_version(client, vault, path)
            metadata = read_response['data']['metadata'].get('custom_metadata', {})
            data = read_response['data'].get('data', {})
            if site['type'] == 'ExternalPersistedCustomSite':
                update_custom_properties(site, metadata, data)
            else:
                update_site_properties(site, metadata, data)
            if 'clientCertificate' in site and site['clientCertificate']:
                for c in certificates['private']:
                    if c['keyName'] == site['clientCertificate']:
                        for c_target in accountSetupTaget['accountSetup']['certificates']['private']:
                            if c['alias'] == c_target['alias']:
                                site['clientCertificate'] = c_target['keyName']
            site.pop('siteName', None)
            resource = 'sites/'
            s_target.headers.update({'Accept': 'application/json'})
            s_target.headers.update({'Content-Type': 'application/json'})
            response_s = s_target.post(target_ST + resource, json=site)

    # UPDATE COMPOSITE ROUTES
    for c_route in compositeRoutes:
        resource = 'routes/'
        s_target.headers.update({'Content-Type': 'application/json'})
        s_target.headers.update({'Accept': 'application/json'})
        getRouteID = s_target.get(target_ST + resource, params=dict(fields='id,steps', account=i, type='COMPOSITE',
                                                                    name=c_route['name']))
        executeRoute = False
        if getRouteID.json()['result'][0]['steps'] and 'executeRoute' in getRouteID.json()['result'][0]['steps'][0]:
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
                    s_target.headers.update({'Accept': 'application/json'})
                    s_target.headers.update({'Content-Type': 'application/json'})
                    create = s_target.post(target_ST + resource, json=source_sub)
                    if create.ok:
                        subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
                        newSubscriptions.append(subscriptionID)
                    logging.info(f"Subscription create status: {create.status_code}, Message: {create.text}")
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
                    if result.ok:
                        data = result.json()
                        data.pop('id')

                        for r_step in data['steps']:
                            if 'precedingStep' in r_step:
                                r_step.pop('precedingStep')
                        s_target.headers.update({'Content-Type': 'application/json'})
                        s_target.headers.update({'Accept': 'application/json'})
                        create = s_target.post(target_ST + resource, json=data)
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
        if subscription['type'] != 'AdvancedRouting' and subscription['folder'] not in targetSites:
            subscription.pop('id')
            for tc in subscription['transferConfigurations']:
                tc.pop('id')
            response = s_target.post(target_ST + resource, json=subscription)
            print(response.text)
