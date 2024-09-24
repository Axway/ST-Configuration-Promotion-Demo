import json
from pprint import pprint

import dotenv
import hvac

from funcsession import *

accountsToMigrate = ['hrisy']

# SETTINGS
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")
s, urlST = Authenticate("ST_NON_PROD")
s.verify = False
s.headers.update({'Accept':'application/json'})
# VARS
vault = 'SecureTransport'
tier = 'non-production'
# Hashi Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
    verify=False
)
client.secrets.kv.v2.configure(
    mount_point=vault,
)
resource = "accounts/"
res = s.get(urlST + resource)
# print(res.json())
allData = res.json()['result']
# print(allData)

def addMetadata(param):
    if param in accountSite and accountSite[param]:
        customMetadata[param] = accountSite[param]
    elif 'customProperties' in accountSite:
        if accountSite['customProperties'][param]:
            customMetadata[param] = accountSite['customProperties'][param]

for account in allData:
    if account['type'] == 'user':
        userName = (account['name'])
        # Writing a secret
        create_response = client.secrets.kv.v2.create_or_update_secret(
            mount_point=vault,
            path=f'accounts/{userName}/user/{tier}',
            secret=dict(userName=userName),
        )
        logging.info("Processing account: %s", userName)
        getAccountSetup = s.get(urlST + 'accountSetup/' + userName)
        #print(getAccountSetup.json())
        accountSetupSites = getAccountSetup.json()['accountSetup']['sites']

        if accountSetupSites:
            for accountSite in accountSetupSites:
                logging.info("Processing site for protocol: %s", accountSite['protocol'])

                create_response = client.secrets.kv.v2.create_or_update_secret(
                    mount_point=vault,
                    path=f'accounts/{userName}/sites/{tier}/{accountSite["name"]}',
                    secret=dict(siteName=accountSite["name"]),
                )
                logging.info(create_response)
                customMetadata = {'type': accountSite['type'], 'protocol': accountSite['protocol']}

                if accountSite['protocol'] == 'smb':
                    addMetadata('smbHost')
                    addMetadata('smbUploadFolder')
                    addMetadata('smbUserName')
                    addMetadata('smbPassword')
                    # print(accountSite)
                elif accountSite['protocol'] == 'pesit':
                    addMetadata('host')
                    addMetadata('port')
                    addMetadata('pesitId')
                elif accountSite['protocol'] == 'http':
                    addMetadata('uri')
                elif accountSite['protocol'] == 'adhoc':
                    customMetadata['fromEmailAddress'] = accountSite['fromEmailAddress']
                    customMetadata['toEmailAddresses'] = accountSite['toEmailAddresses']
                elif accountSite['protocol'] == 's3':
                    customMetadata['s3Region'] = accountSite['customProperties']['s3Region']
                    customMetadata['s3UploadDestination'] = accountSite['customProperties']['s3UploadDestination']
                    addMetadata('s3DownloadObjectKey')
                    addMetadata('s3SecretKey')
                    addMetadata('s3AccessKey')
                    customMetadata['s3Bucket'] = accountSite['customProperties']['s3Bucket']

                elif accountSite['protocol'] == 'folder':
                    customMetadata['downloadFolder'] = accountSite['downloadFolder']
                    customMetadata['uploadFolder'] = accountSite['uploadFolder']
                elif accountSite['protocol'] == 'as2':
                    customMetadata['senderAs2Id'] = accountSite['senderAs2Id']
                    customMetadata['receiverAs2Id'] = accountSite['receiverAs2Id']
                    customMetadata['as2Url'] = accountSite['as2Url']
                elif accountSite['protocol'] == 'azure-file':
                    addMetadata('azurefileSpSecret')
                    addMetadata('azurefileSpEndpoint')
                    addMetadata('azurefileEndpointSuffix')
                    addMetadata('azurefileDownloadFolder')

                else:
                    customMetadata['host'] = accountSite['host']
                    customMetadata['port'] = accountSite['port']
                    addMetadata('userName')
                    addMetadata('clientCertificate')
                    if accountSite['usePassword']:
                        addMetadata('password')
                    if accountSite['downloadFolder']:
                        customMetadata['downloadFolder'] = accountSite['downloadFolder']


                #print(customMetadata)
                create_response = client.secrets.kv.v2.update_metadata(
                    mount_point=vault,
                    path=f'accounts/{userName}/sites/{tier}/{accountSite["name"]}',
                    custom_metadata=customMetadata
                )
                logging.info("Account: %s; Site: %s; custom metadata added: %s", userName,
                             accountSite['name'], customMetadata)
                if create_response.ok:
                    logging.info("Site: %s created or updated successfully", accountSite['name'])
                else:
                    logging.error(f"Process exited with status code: {create_response.status_code}; "
                                  f"details: {create_response.text}")

        accountSetupRoutes = getAccountSetup.json()['accountSetup']['routes']

        if accountSetupRoutes:
            for route in accountSetupRoutes:
                #print(route['name'], route['routeTemplate'], route['account'])
                logging.info("Processing route for account: %s", route['account'])

                create_response = client.secrets.kv.v2.create_or_update_secret(
                    mount_point=vault,
                    path=f'accounts/{userName}/routes/{tier}/{route["name"]}',
                    secret=dict(routeTemplateID=route['routeTemplate']),
                )
                logging.info(create_response)

resource = "routes/"
params = {'type': 'TEMPLATE'}
res = s.get(urlST + resource, params = params)
routeTemplates = res.json()['result']
routeTemplatesStepsMap = []
for i in routeTemplates:
    routeTemplatesStepList = []
    logging.info("Processing route template: %s", i['name'])
    if i['steps']:
        for step in i['steps']:
            #link = s.get(step['metadata']['links']['executeRoute'])
            #print(link.json())
            #print(json.dumps(step['metadata']['links']['executeRoute'], indent=4))
            routeTemplatesStepList.append(step['metadata']['links']['executeRoute'])
            routeTemplatesStepsMap.append({i['id']: routeTemplatesStepList})


    # print(routeTemplatesStepsMap)
    create_response = client.secrets.kv.v2.create_or_update_secret(
        mount_point=vault,
        path=f'routeTemplates/{tier}/{i["name"]}',
        secret=dict(routeTemplateID=i['id']),
    )
    logging.info(create_response)
    customMetadata = {'conditionType': i['conditionType'], 'failureEmailNotification': i['failureEmailNotification'],
                      'successEmailNotification': i['successEmailNotification'],
                      'triggeringEmailNotification': i['triggeringEmailNotification']}
    if i['failureEmailTemplate']:
        customMetadata['failureEmailTemplate'] = i['failureEmailTemplate']
    if i['failureEmailName']:
        customMetadata['failureEmailName'] = i['failureEmailName']
    if i['successEmailTemplate']:
        customMetadata['successEmailTemplate'] = i['successEmailTemplate']
    if i['successEmailName']:
        customMetadata['successEmailName'] = i['successEmailName']
    if i['triggeringEmailName']:
        customMetadata['triggeringEmailName'] = i['triggeringEmailName']
    if i['triggeringEmailTemplate']:
        customMetadata['triggeringEmailTemplate'] = i['triggeringEmailTemplate']



    create_response = client.secrets.kv.v2.update_metadata(
        mount_point=vault,
        path=f'routeTemplates/{tier}/{i["name"]}',
        custom_metadata=customMetadata
    )
params = {'limit': 1000}
res = s.get(urlST + resource, params=params)

# print(res.json())
allRoutes = res.json()['result']
updatedSimpleRoutes = []
for i in allRoutes:

    if i['type'] == 'SIMPLE':
        simpleRoute = i
        simpleRoute.pop('metadata')
        if simpleRoute['steps']:
            for step in simpleRoute['steps']:
                step.pop('metadata')

            #print(json.dumps(step, indent=4))
        # print(json.dumps(simpleRoute, indent=4))
        updatedSimpleRoutes.append(simpleRoute)
    # elif i['type'] == 'TEMPLATE':
    #     templateRoute = i
    #     print(json.dumps(i, indent=4))

#print(json.dumps(updatedSimpleRoutes, indent=4))
    # response = s.delete(urlST + resource + i['id'])
    # print(response.status_code)

# START IMPORT INTO TARGET ST

sess, targetST = Authenticate("ST_PROD")
resource = 'routes/'

for i in routeTemplates:
    checkIfExist = sess.head(targetST + resource + i['id'])
    if not checkIfExist.ok:
        response = sess.post(targetST + resource, json=i)
        print(response.text)
res = sess.get(targetST + resource)
# for i in res.json()['result']:
#     print(i['id'])
    # response = sess.delete(targetST + resource + i['id'])
    # print(response.status_code)
# for i in updatedSimpleRoutes:
#     i.pop('id')
#     if i['steps']:
#         for step in i['steps']:
#             step.pop('precedingStep')
#     response = sess.post(targetST + resource, json=i)
#
#     print(response.headers['Location'])
#     print(response.text)
    # print(json.dumps(i, indent=4))
resource = 'accountSetup/'
for i in accountsToMigrate:
    res = s.get(urlST + resource + i)
    accountSetup = res.json()
    subscriptions = accountSetup['accountSetup']['subscriptions'].copy()
    accountSetup['accountSetup']['subscriptions'].clear()
    compositeRoutes = accountSetup['accountSetup']['routes'].copy()

    accountSetup['accountSetup']['routes'].clear()

    # print(json.dumps(result, indent=4))
    res = sess.post(targetST + resource, json=accountSetup)
    print(res.text)
    resource = 'routes/'
    for cr in compositeRoutes:
        print(json.dumps(cr['subscriptions'], indent=4))
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
                # if 'precedingStep' in data['steps']:
                #     data['steps'].pop('precedingStep')
                # print(json.dumps(data, indent=4))
                create = sess.post(targetST + resource, json=data)
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
                print(create.text)
                if create.ok:
                    subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
                    newSubscriptions.append(subscriptionID)
        cr['subscriptions'] = newSubscriptions



        cr.pop('id')
        #print(json.dumps(cr, indent=4))
        pprint(cr)
        res = sess.post(targetST + resource, json=cr)
        print(res.text)
        for subscription in cr['subscriptions']:
            print(subscription)
    # resource = 'subscriptions/'
    # for sub in subscriptions:
    #     subscriptionOldID = sub['id']
    #     for tc in sub['transferConfigurations']:
    #         tc.pop('id')
    #
    #     create = sess.post(targetST + resource, json=sub)
    #     if create.ok:
    #         subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
    #     #print(create.text, create.status_code, create.headers)
    # resource = 'routes/'
    # params = {'account': i}
    # res = sess.get(targetST + resource, params = params)
    # result = res.json()
    #print(json.dumps(result['result'], indent=4))