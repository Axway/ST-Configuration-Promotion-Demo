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
auth_method = 'appRole'
# auth_method = 'cert'

# Open and read the JSON file
with open('resources/externalStore.json') as file:
    json_data = json.load(file)
json_data['name'] = 'HashiCorp'
json_data['attributePrefix'] = ''
json_data['authHeader'] = 'X-Vault-Token'
json_data['pathPrefix'] = '$.data.data'
json_data['auth']['token'] = '$.auth.client_token'
json_data['auth']['baseUrl'] = hashiHost
json_data['auth']['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
json_data['auth']['tls']['caAliases'] = ['hashi']
json_data['headers'] = {"X-Vault-Token": "${vault.api.auth.token}"}
json_data['auth']['tls']['skipHostNameVerification'] = True
json_data['baseUrl'] = hashiHost
json_data['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
del json_data['tls']['ciphers']
json_data['tls']['caAliases'] = ['hashi']
json_data['tls']['skipHostNameVerification'] = True
json_data['uri'] = path
del json_data['auth']['tls']['ciphers']

if auth_method == 'appRole':
    json_data['auth']['uri'] = '/v1/auth/approle/login'
    json_data['auth']['body'] = {"secret_id": secret_id, "role_id": role_id}
    del json_data['tls']['certificateAlias']
    del json_data['auth']['tls']['certificateAlias']
elif auth_method == 'cert':
    json_data['auth']['tls']['certificateAlias'] = 'hashi_auth'
    json_data['tls']['certificateAlias'] = 'hashi_auth'
    json_data['auth']['body'] = {'name': 'st-ca'}
    json_data['auth']['uri'] = '/v1/auth/cert/login'

pprint.pp(json_data)
resource = 'configurations/externalStores/'
response = s_target.post(target_ST + resource, json=json_data)
print(response.text)

# Sample usage in ST
# ${fetch('HashiCorp','/accounts/hrisy/sites/production/s3','s3SecretKey')}
# ${fetch('HashiCorp','/accounts/hrisy/sites/production/s3','aws_bucketName')}
