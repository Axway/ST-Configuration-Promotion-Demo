# This is provided as-is, and you should run it at your own risk.
# This is provided in order to provide usage examples and Axway cannot guarantee it is fit for production,
# or provide ongoing support for it.
# Author: Hristina Stoykova

from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata
import json
import warnings
import dotenv
from func import *
import hvac
from requests_toolbelt.utils import dump
import os
import copy


# Load environment variables
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)

# Suppress specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

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




# FUNCTIONS
def extract_pgp_keys(raw_content):
    # Decode the bytes to a string
    raw_content_str = raw_content.decode('utf-8')  # assuming the content is UTF-8 encoded

    # Regular expressions to capture the public and private keys
    public_key_pattern = r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----'
    private_key_pattern = r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----'

    # Find all matches
    public_key_matches = re.findall(public_key_pattern, raw_content_str, re.DOTALL)
    private_key_matches = re.findall(private_key_pattern, raw_content_str, re.DOTALL)

    # Extract the keys
    public_key = public_key_matches[0] if public_key_matches else None
    private_key = private_key_matches[0] if private_key_matches else None

    return public_key, private_key


### IMPORT TO TARGET ST
## MIGRATE TEMPLATE ROUTES
resource = "routes/"
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})
migrate_route_templates(s_source, source_ST,s_target, target_ST, resource)



### HANDLE ACCOUNTS MIGRATION

resource = 'accountSetup/'
for i in accountsToMigrate:
    res = s_source.get(source_ST + resource + i)
    accountSetup = res.json()
    # ACCOUNT SETTINGS
    accountSetup['accountSetup']['account']['disabled'] = True
    # CERTIFICATE SETTINGS
    certificates = copy.deepcopy(accountSetup['accountSetup']['certificates'])
    accountSetup['accountSetup']['certificates']['partner'].clear()
    accountSetup['accountSetup']['certificates']['private'].clear()
    accountSetup['accountSetup']['certificates']['login'].clear()
    # ROUTES
    compositeRoutes = copy.deepcopy(accountSetup['accountSetup']['routes'])
    for route in accountSetup['accountSetup']['routes']:
        route['subscriptions'].clear()
        for step in route['steps']:
            if step['type'] == "ExecuteRoute":
                route['steps'].remove(step)
    # SUBSCRIPTIONS
    subscriptions = copy.deepcopy(accountSetup['accountSetup']['subscriptions'])
    for subscription in accountSetup['accountSetup']['subscriptions']:
        if subscription['type'] != 'AdvancedRouting':
            for tc in subscription['transferConfigurations']:
                tc.pop('id')
        else:
            accountSetup['accountSetup']['subscriptions'].remove(subscription)
    subscriptions = copy.deepcopy(accountSetup['accountSetup']['subscriptions'])
    # TRANSFER SITES
    for site in accountSetup['accountSetup']['sites']:
        path = f'accounts/{i}/sites/{tier}/{site["name"]}'
        read_response = read_secret_version(client, vault, path)
        metadata = read_response['data']['metadata'].get('custom_metadata', {})
        data = read_response['data'].get('data', {})

        if site['type'] == 'ExternalPersistedCustomSite':
            update_custom_properties(site, metadata, data)
        else:
            update_site_properties(site, metadata, data)

        site.pop('siteName', None)
    if certificates:
        resource = 'certificates/'
        fields = []
        del s_source.headers['content-type']
        if certificates['partner']:
            for cert in certificates['partner']:
                params = {'account': i, 'type': cert['type'], 'usage': 'partner', 'name': cert['alias']}
                checkIfExists = s_target.get(target_ST + resource, params=params)
                checkIfExistsResult = checkIfExists.json()

                if cert['type'] == 'x509' and not checkIfExistsResult['result']:
                    s_source.headers.update({'Accept': 'multipart/mixed'})
                    cert_res = s_source.get(source_ST + "certificates/" + cert['keyName'])
                    text = cert_res.text
                    # # Regular expression to extract the boundary part
                    boundary_pattern = r'--Boundary_\d+_\d+_\d+'
                    # EXTRACT THE DIFFERENT PARTS
                    boundary_match = re.search(boundary_pattern, text)
                    if not boundary_match:
                        raise ValueError("Boundary not found in the text")
                    boundary = boundary_match.group()
                    # Split the text by the boundary
                    parts = re.split(boundary, text)
                    jsonData = json.loads(delete_line_from_cert( parts[1], 1))
                    x509 = delete_headers_from_cert(parts[2])
                    keyname = cert['keyName'] = cert['alias']
                    cert['generate'] = False
                    del cert['caPassword']
                    del cert['certificatePassword']
                    files = {f"{keyname}": (x509, 'application/octet-stream', {'keyname': f"{keyname}", 'encoded': 'false'})}
                    for name, (contents, mimetype, headers) in files.items():
                        rf = RequestField(name=name, data=contents, headers=headers)
                        rf.make_multipart(content_disposition='attachment', content_type=mimetype)
                        fields.append(rf)
                    accountSetup['accountSetup']['certificates']['partner'].append(cert)
                else:
                    certificates['partner'].remove(cert)
        if certificates['private']:

            for cert in certificates['private']:
                params = {'account': i, 'type': cert['type'], 'usage': 'private', 'name': cert['alias']}
                checkIfExists = s_target.get(target_ST + resource, params=params)
                checkIfExistsResult = checkIfExists.json()
                if cert['type'] == 'pgp' and not checkIfExistsResult['result']:
                    s_source.headers.update({'Accept': 'multipart/mixed'})
                    params = {'password': 'password', 'exportPrivateKey': 'true'}
                    cert_res = s_source.get(source_ST + "certificates/" + cert['keyName'], params=params)
                    text = cert_res.content
                    boundary_pattern = r'boundary=([a-zA-Z0-9_-]+)'
                    # EXTRACT THE DIFFERENT PARTS
                    match = re.search(boundary_pattern, cert_res.headers['Content-Type'])
                    if not match:
                        raise ValueError("Boundary not found in the text")
                    boundary = ('--' + match.group(1)).encode()
                    parts = text.split(boundary)
                    # Loop through each part and process
                    for part in parts:
                        part = part.strip()  # Clean the part to avoid any leading/trailing spaces

                        if not part:
                            continue
                        # Check if part is JSON (looking for Content-Type: application/json)
                        if b"Content-Type: application/json" in part:
                            try:
                                json_start = part.index(b"{")  # Find the start of the JSON data
                                json_end = part.rindex(b"}")  # Find the end of the JSON data
                                raw_json = part[json_start:json_end + 1]
                                json_data = json.loads(raw_json.decode('utf-8'))
                            except Exception as e:
                                print("Error decoding JSON:", e)
                    public_pgp, private_pgp = extract_pgp_keys(text)
                    pgp_import = public_pgp + '\n' + private_pgp

                    keyname = cert['keyName'] = cert['alias']
                    cert['generate'] = False
                    cert['certificatePassword'] = params['password']
                    files = {
                        f"{keyname}": (pgp_import, 'application/octet-stream', {'keyname': f"{keyname}", 'encoded': 'false'})}
                    for name, (contents, mimetype, headers) in files.items():
                        rf = RequestField(name=name, data=contents, headers=headers)
                        rf.make_multipart(content_disposition='attachment', content_type=mimetype)
                        fields.append(rf)
                    accountSetup['accountSetup']['certificates']['private'].append(cert)
        files = {"accountSetup": (json.dumps(accountSetup), "application/json")}
        for name, (contents, mimetype) in files.items():
            rf = RequestField(name=name, data=contents)
            rf.make_multipart(content_disposition='attachment', content_type=mimetype)
            fields.append(rf)
        post_body, content_type = encode_multipart_formdata(fields)
        content_type = ''.join(('multipart/mixed',) + content_type.partition(';')[1:])


    # IMPORT ACCOUNT, SITES, COMPOSITE ROUTES, AND NON AR SUBSCRIPTIONS
    resource = 'accountSetup/'
    if not (accountSetup['accountSetup']['certificates']['partner'] or accountSetup['accountSetup']['certificates']['private']):
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
