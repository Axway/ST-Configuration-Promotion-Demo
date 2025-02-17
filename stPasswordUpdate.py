import json
import warnings
from textwrap import indent

import dotenv
from func import *

import hvac

siteToMigrate = [{'hrisy': 'SMB'}]

# SETTINGS
warnings.filterwarnings("ignore", category=DeprecationWarning)
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")

# Authenticate with ST
s_source, source_ST = Authenticate("ST_NON_PROD")
s_source.verify = False
s_source.headers.update({'Accept': 'application/json'})
s_target, target_ST = Authenticate("ST_PROD")
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

# EXPORT FROM SOURCE ST

resource = "sites/"
for sites in siteToMigrate:
    for k, v in sites.items():
        params = {'account': k, 'name': v}
        res = s_target.get(target_ST + resource, params=params)
        site = res.json()['result'][0]
        path = f'accounts/{k}/sites/{tier}/{v}'
        read_response = read_secret_version(client, vault, path)
        data = read_response['data'].get('data', {})
        print(data)
        del data['siteName']
        print(data)
        for key, value in data.items():
            site['customProperties'][key] = value
            print(data)
            payload = [
                {
                    "op": "replace",
                    "path": f"/customProperties/{key}",
                    "value": f"{value}"
                }
            ]
            response = s_target.patch(target_ST + resource + site['id'], json=payload)
            logging.info(f"Password update status {response.status_code}; Message: {response.text}")
