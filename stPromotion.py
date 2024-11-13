import warnings
from argparse import ArgumentParser

import dotenv
from funcsession import *
import hvac
import sys
from requests_toolbelt.utils import dump
# Import the email modules we'll need
from email import policy
from email.parser import BytesParser
import os
import email
import mimetypes
from requests_toolbelt.multipart import decoder

from email.policy import default

from argparse import ArgumentParser


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
    s.headers.update({'Accept': 'application/json'})
    checkIfExist = sess.head(targetST + resource + i['id'])
    if not checkIfExist.ok:
        response = sess.post(targetST + resource, json=i)
        logging.info(f"Route Template status {response.status_code}; Message: {response.text}")

resource = 'accountSetup/'
for i in accountsToMigrate:
    s.headers.update({'Accept': 'application/json'})
    res = s.get(urlST + resource + i)
    accountSetup = res.json()
    subscriptions = accountSetup['accountSetup']['subscriptions'].copy()
    accountSetup['accountSetup']['subscriptions'].clear()
    compositeRoutes = accountSetup['accountSetup']['routes'].copy()
    certificates = accountSetup['accountSetup']['certificates'].copy()

    accountSetup['accountSetup']['routes'].clear()
    accountSetup['accountSetup']['account']['disabled'] = True

    for site in accountSetup['accountSetup']['sites']:
        read_response = client.secrets.kv.v2.read_secret_version(mount_point=vault,
                                                                 path=f'accounts/{i}/sites/{tier}/{site["name"]}')

        if site['type'] == 'ExternalPersistedCustomSite':
            if read_response['data']['metadata']['custom_metadata']:
                for k, v in read_response['data']['metadata']['custom_metadata'].items():
                    site['customProperties'][k] = read_response['data']['metadata']['custom_metadata'][k]
            if read_response['data']['data']:
                for k, v in read_response['data']['data'].items():
                    site['customProperties'][k] = read_response['data']['data'][k]

        else:
            if read_response['data']['metadata']['custom_metadata']:
                for k, v in read_response['data']['metadata']['custom_metadata'].items():
                    site[k] = read_response['data']['metadata']['custom_metadata'][k]

            if read_response['data']['data']:
                for k, v in read_response['data']['data'].items():
                    site[k] = read_response['data']['data'][k]



    if certificates:
        if certificates['private']:
            for cert in certificates['private']:
                print(cert)
                s.headers.update({'accept': 'multipart/mixed'})
                del s.headers['content-type']
                params = {'password': '%D0%BF%D0%B0%D1%81%D1%81%D0%B2%D0%BE%D1%80%D0%B4', 'exportPrivateKey': 'true'}
                cert_res  = s.get(urlST + "certificates/" + str(cert['keyName']), params=params)
                data = dump.dump_all(cert_res)

                multipart_data = decoder.MultipartDecoder.from_response(cert_res)

                for part in multipart_data.parts:
                    #print(part.content)  # Alternatively, part.text if you want unicode
                    print(type(part.headers))
                    if part.headers['Content-Type'] == 'application/json':
                        print(part.text)
                # with open('multipart.msg', 'wb') as f:
                #     f.write(cert_res.content)
                with open('multipart.msg', 'rb') as fp:
                    msg = BytesParser(policy=policy.default).parse(fp)









                counter = 1
                for part in msg.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue

                    filename = part.get_filename()
                    if not filename:
                        ext = mimetypes.guess_extension(part.get_content_type())
                        if not ext:
                            # Use a generic bag-of-bits extension
                            ext = '.bin'
                        filename = f'part-{counter:03d}{ext}'
                    counter += 1
                    with open(filename, 'wb') as fp:
                        fp.write(part.get_payload(decode=True))

    s.headers.update({'Accept': 'application/json'})
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
