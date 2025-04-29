
import pprint
import warnings
import dotenv
import os
import json
from stAPIClient.Client import Authenticator
from typing import Literal, Optional

class CreateExternalVault:
    def __init__(
            self,
            env_file: Optional[str] =".env",
            auth_method: Literal['appRole','cert']=None,
            config: Optional[str]=None
    ):
        # Load environment variables
        dotenv.load_dotenv(env_file)
        self.hashiToken = os.environ.get("VAULT_TOKEN")
        self.hashiHost = os.environ.get("VAULT_HOST")
        self.role_id = os.environ.get("VAULT_ROLE_ID")
        self.secret_id = os.environ.get("VAULT_SECRET_ID")
        self.auth_method = auth_method
        self.path = '/v1/SecureTransport/data/'
        self.config = config

        # Create a HttpClient instance
        self.s_target = Authenticator("ST_PROD")

        # SETTINGS
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        # Load JSON data from file
        with open('resources/externalStore.json') as file:
            self.json_data = json.load(file)

        # Update JSON data with common settings
        self.json_data['name'] = 'HashiCorp'
        self.json_data['attributePrefix'] = ''
        self.json_data['authHeader'] = 'X-Vault-Token'
        self.json_data['pathPrefix'] = '$.data.data'
        self.json_data['auth']['token'] = '$.auth.client_token'
        self.json_data['auth']['baseUrl'] = self.hashiHost
        self.json_data['auth']['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
        self.json_data['auth']['tls']['caAliases'] = ['hashi']
        self.json_data['headers'] = {"X-Vault-Token": "${vault.api.auth.token}"}
        self.json_data['auth']['tls']['skipHostNameVerification'] = True
        self.json_data['baseUrl'] = self.hashiHost
        self.json_data['tls']['protocols'] = ['TLSv1.2', 'TLSv1.3']
        del self.json_data['tls']['ciphers']
        self.json_data['tls']['caAliases'] = ['hashi']
        self.json_data['tls']['skipHostNameVerification'] = True
        self.json_data['uri'] = self.path
        del self.json_data['auth']['tls']['ciphers']

    def authenticate_approle(self):
        self.json_data['auth']['uri'] = '/v1/auth/approle/login'
        self.json_data['auth']['body'] = {"secret_id": self.secret_id, "role_id": self.role_id}
        del self.json_data['tls']['certificateAlias']
        del self.json_data['auth']['tls']['certificateAlias']
        return self.json_data

    def authenticate_cert(self):
        self.json_data['auth']['tls']['certificateAlias'] = 'hashi_auth'
        self.json_data['tls']['certificateAlias'] = 'hashi_auth'
        self.json_data['auth']['body'] = {'name': 'st-ca'}
        self.json_data['auth']['uri'] = '/v1/auth/cert/login'
        return self.json_data

    def login(self):
        response = self.s_target.login()
        return response

    def post_configuration(self):
        if self.auth_method == 'appRole':
            config_data = self.authenticate_approle()
        elif self.auth_method == 'cert':
            config_data = self.authenticate_cert()
        else:
            raise ValueError("Invalid authentication method")

        pprint.pp(config_data)
        resource = '/configurations/externalStores/'
        response = self.s_target.post(request_path=resource, params=config_data)
        return response


# Example usage
createStore = CreateExternalVault(auth_method='cert')
login_response = createStore.login()
post_response = createStore.post_configuration()
print(post_response)

# Example usage in ST
# ${fetch('HashiCorp','/accounts/hrisy/sites/production/s3','aws_secretKey')}
# ${fetch('HashiCorp','/accounts/hrisy/sites/production/s3','aws_bucketName')}
