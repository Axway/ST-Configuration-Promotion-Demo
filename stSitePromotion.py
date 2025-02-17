import warnings
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
        res = s_source.get(source_ST + resource, params=params)
        site = res.json()['result'][0]
        path = f'accounts/{k}/sites/{tier}/{v}'
        read_response = read_secret_version(client, vault, path)
        metadata = read_response['data']['metadata'].get('custom_metadata', {})
        data = read_response['data'].get('data', {})
        if site['type'] == 'ExternalPersistedCustomSite':
            update_custom_properties(site, metadata, data)
        else:
            update_site_properties(site, metadata, data)

        checkIfExists = s_target.get(target_ST + resource, params={'account': k,
                                                                   'name': v})
        checkIfExistsResult = checkIfExists.json()
        if checkIfExistsResult['resultSet']['totalCount'] == 0:
            response = s_target.post(target_ST + resource, json=site)
            if response.ok:
                logging.info(f"Site migration status {response.status_code}; Message: {response.text}")
            else:
                print(response.text)
        else:
            logging.info(f"Site {site['name']} already exists, updating...")
            response = s_target.put(target_ST + resource + checkIfExistsResult['result'][0]['id'], json=site)
            if response.ok:
                logging.info(f"Site {site['name']} update successful")
            else:
                print(response.text)
