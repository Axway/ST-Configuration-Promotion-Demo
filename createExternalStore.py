import pprint
import warnings

import dotenv
from func import *

s_target, target_ST = Authenticate("ST_PROD")
s_target.verify = False
s_target.headers.update({'Accept': 'application/json'})
s_target.headers.update({'Content-Type': 'application/json'})

# SETTINGS
warnings.filterwarnings("ignore", category=DeprecationWarning)
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")
role_id = os.environ.get("VAULT_ROLE_ID")
secret_id = os.environ.get("VAULT_SECRET_ID")
path = f'/v1/SecureTransport/data/'

# Open and read the JSON file
with open('resources/externalStore.json', 'r') as file:
    json_data = json.load(file)

# Print the data
json_data['name'] = 'HashiCorp'
json_data['attributePrefix'] = ''
json_data['authHeader'] = 'X-Vault-Token'
json_data['pathPrefix'] = '$.data.data'
json_data['auth']['token'] = '$.auth.client_token'
json_data['auth']['baseUrl'] = hashiHost
json_data['auth']['uri'] = '/v1/auth/approle/login'
json_data['auth']['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
json_data['auth']['tls'].pop('ciphers')
json_data['auth']['tls'].pop('caAliases')
json_data['auth']['tls'].pop('certificateAlias')
json_data['auth']['tls']['skipHostNameVerification'] = True
json_data['baseUrl'] = hashiHost
json_data['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
json_data['tls'].pop('ciphers')
json_data['tls'].pop('caAliases')
json_data['tls'].pop('certificateAlias')
json_data['tls']['skipHostNameVerification'] = True
json_data['uri'] = path
json_data['auth']['body'] = {"secret_id": secret_id, "role_id": role_id}



pprint.pp(json_data)
resource = 'configurations/externalStores/'
response = s_target.post(target_ST + resource, json=json_data)
print(response.text)


# ${fetch('HashiCorp','/accounts/hrisy/sites/production/s3','s3SecretKey')}
