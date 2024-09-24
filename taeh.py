import os

import dotenv
import requests


# SETTINGS
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")


st_secret = os.environ.get("ST_SECRET")
# VARS
role_id = {'request_id': 'f8f142b7-f126-9961-8cce-bd727b8ea002', 'lease_id': '', 'renewable': False, 'lease_duration': 0, 'data': 
    {'role_id': 'ca6ef0f2-d489-cf6b-505b-4ceb056e6f9f'}, 'wrap_info': None, 'warnings': None, 'auth': None, 'mount_type': 'approle'}
secret_id = {'request_id': '36689977-a91b-076f-b062-ee8f83b40bd7', 'lease_id': '', 'renewable': False, 'lease_duration': 0, 'data':
    {'secret_id': '2c308324-eea4-cb1c-d6a7-843d43dfdc5b', 'secret_id_accessor': '8190f663-746e-53b9-081b-2d897785ab9f', 'secret_id_num_uses': 0,
     'secret_id_ttl': 0}, 'wrap_info': None, 'warnings': None, 'auth': None, 'mount_type': 'approle'}

headers={'X-Vault-Token': hashiToken}
# response = requests.post(hashiHost + '/v1/sys/auth/approle', json={"type": "approle"}, headers=headers, verify=False)
# print(response.status_code, response.text)
# appRole = response.content
# print(appRole)
#
payload = { "policy" : "path \"st_secret/data/taeh\" \n {\n capabilities=[\"read\"]\n}\n" }
response = requests.post(hashiHost + '/v1/sys/policies/acl/st-secret-readonly', json=payload, headers=headers, verify=False)
print(response.status_code, response.text)
stPolicy = response.content
print(stPolicy)

# payload={"bind_secret_id": True,   "local_secret_ids": False,  "token_type":"batch"}
# resource = '/v1/auth/approle/role/st_app'
# response = requests.post(hashiHost + resource, json=payload, headers=headers, verify=False)
# print(response.status_code, response.text)
# appRoleCreate = response.content
# print(appRoleCreate)
#
# resource = '/v1/auth/approle/role/st_app/role-id'
# response = requests.get(hashiHost + resource, headers=headers, verify=False)
# print(response.status_code, response.text)
# roleID = response.json()
# print(roleID)

# resource = '/v1/auth/approle/role/st_app/secret-id'
# payload = {"ttl": "0"}
# response = requests.post(hashiHost + resource, json=payload, headers=headers, verify=False)
# print(response.status_code, response.text, response.json())
# roleID = response.json()
# print(roleID)

resource = '/v1/auth/approle/role/st_app/policies'
payload = {"token_policies": [
    "st-secret-readonly"
  ] }
response = requests.post(hashiHost + resource, json=payload, headers=headers, verify=False)
print(response.status_code, response.text)
roleID = response.content
print(roleID)

resource = '/v1/sys/mounts/st_secret'
payload = {"token_policies": [
    "st-secret-readonly"
  ] }
response = requests.post(hashiHost + resource, json={ "type":"kv-v2" }, headers=headers, verify=False)
print(response.status_code, response.text)


resource = '/v1/st_secret/data/taeh'
payload = {"data": {"secret": st_secret}}
response = requests.post(hashiHost + resource, json=payload, headers=headers, verify=False)
print(response.status_code, response.text)


