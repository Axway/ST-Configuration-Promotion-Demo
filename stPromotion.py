import json
import warnings
from textwrap import indent

import dotenv
from funcsession import *

import hvac

accountsToMigrate = ['hrisy']


# SETTINGS
warnings.filterwarnings("ignore", category=DeprecationWarning)
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")
s, urlST = Authenticate("ST_NON_PROD")
s.verify = False
s.headers.update({'Accept':'application/json'})

# VARS
vault = 'SecureTransport'
tier = 'production'
# Hashi Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
    verify=False
)

# EXPORT FROM SOURCE ST

resource = "routes/"
params = {'type': 'TEMPLATE'}
res = s.get(urlST + resource, params = params)
routeTemplates = res.json()['result']

# START IMPORT INTO TARGET ST





sess, targetST = Authenticate("ST_PROD")
resource = 'routes/'

for i in routeTemplates:
    checkIfExist = sess.head(targetST + resource + i['id'])
    if not checkIfExist.ok:
        response = sess.post(targetST + resource, json=i)
        logging.info(f"Route Template status {response.status_code}; Message: {response.text}")

resource = 'accountSetup/'
for i in accountsToMigrate:

    res = s.get(urlST + resource + i)
    accountSetup = res.json()
    subscriptions = accountSetup['accountSetup']['subscriptions'].copy()
    accountSetup['accountSetup']['subscriptions'].clear()
    compositeRoutes = accountSetup['accountSetup']['routes'].copy()

    accountSetup['accountSetup']['routes'].clear()
    accountSetup['accountSetup']['account']['disabled'] = True

    for site in accountSetup['accountSetup']['sites']:
        read_response = client.secrets.kv.v2.read_secret_version(mount_point=vault,
                                                                 path=f'accounts/{i}/sites/{tier}/{site["name"]}')
        if site['protocol'] == 's3':

            site['customProperties']['s3Bucket'] = read_response['data']['metadata']['custom_metadata']['s3Bucket']
            site['customProperties']['s3AccessKey'] =  read_response['data']['data']['s3AccessKey']
            site['customProperties']['s3SecretKey'] = read_response['data']['data']['s3SecretKey']
        elif site['protocol'] == 'azure-file':

            site['customProperties']['azurefileSpSecret'] = read_response['data']['data']['azurefileSpSecret']
            site['customProperties']['azurefileAccountKey'] = read_response['data']['data']['azurefileAccountKey']
        elif site['protocol'] == 'SharePoint':
            site['customProperties']['sharepointApplicationId'] = read_response['data']['data']['sharepointApplicationId']
            site['customProperties']['sharepoint_password'] = read_response['data']['data']['sharepoint_password']
        elif site['protocol'] == 'http':
            site['password'] = read_response['data']['data'][
                'password']
        elif site['protocol'] == 'smb':

            site['customProperties']['smbPassword'] = read_response['data']['data']['smbPassword']


    res = sess.post(targetST + resource, json=accountSetup)
    logging.info(f"accountSetup status: {res.status_code}, Message: {res.text}")
    resource = 'routes/'
    for cr in compositeRoutes:
        # print(json.dumps(cr['subscriptions'], indent=4))
        newSubscriptions = []
        for step in cr['steps']:

            routeURI = step['metadata']['links']['executeRoute']
            result = s.get(routeURI)
            if result.ok:
                data = result.json()
                data.pop('id')
                for st in data['steps']:
                    if 'precedingStep' in st:
                        st.pop('precedingStep')

                create = sess.post(targetST + resource, json=data)
                if create.ok:
                    pass
                else:
                    print(create.text)
                executeRouteID = create.headers['Location'].rsplit('/', 1)[-1]
                step['executeRoute'] = executeRouteID
        for sb in cr['subscriptions']:
            routeURI = f"{urlST}subscriptions/{sb}"
            result = s.get(routeURI)
            subData = result.json()
            subscriptionOldID = subData['id']
            for tc in subData['transferConfigurations']:
                tc.pop('id')

                create = sess.post(targetST + 'subscriptions', json=subData)

                if create.ok:
                    subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
                    newSubscriptions.append(subscriptionID)
                else:
                    logging.info(f"Subscription create status: {create.status_code}, Message: {create.text}")
        cr['subscriptions'] = newSubscriptions



        cr.pop('id')
        #print(json.dumps(cr, indent=4))
        res = sess.post(targetST + resource, json=cr)
        logging.info(f"Composite Route create status: {res.status_code}, Message: {res.text}")
