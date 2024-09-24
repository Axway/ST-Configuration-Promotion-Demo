import os

import dotenv
import requests

from STWC_OAuth import token

# SETTINGS
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")

st_secret = 'wsaKucHdzc+qAOguAFgECImJbllKV/CEbPZ3P8IwgnsLO/2DBvrHsEnk4JBv1kDGqa07yjtFXzkkK0VVtelm0/hNpAh0F4ZAn0aLvtlRnhUqi0GMwbn4XjhyrU/2znfV/rtQhkFtCttROrnTMIy0oNzkfFZkTZQstfc20CmvvbrIII7BvVED+2bNkIw0rP6F9LdQ8iCS22EfgkvL5p9wEeunQx+kgylLJGErVSC4E8L4urc1+hqgUDkzCT2PHVwE0k4iF1xCZE2Ho4sbLmXke9fZEUJiQCA19vpNJhIYJ4oueeB2L84r7A/OmJe8FgoaW/jMWclVCnrUYj34oZs78z7eRa3Hvvc9FvCYUq1f/PwhJsp+dFTHqf2DIx/tsssb9PtC/S4DcUojvgibaWSyxAJ2OL31RCETGoRPosbe27eKZsRsrrdJzkCwE6d3u15bVQ2o8pNyy8wI1eM0M9Oc2hof2EyQHtvuvQlPi4QJnYO+WRyfurRDvSYDaV2uUC3UEwhI46d88gPKNF48rsA1Mo9uDGjlyBqFp4HiJQ69LL0rXGZ5HI/MlFPquPFPt8yUlheEIZ6ioNQ5g8zaXa1ZvjR1LdtS7/4W2jYRGsC3ySNXGHP4LA7a4RxFhXdyfrwyWBgOCoLCXwGLzph1ww4CLco28qVm6lJQzYME2N8QQy4LK/5bGX1C4UtXevACzkd1S3yyte2j+oflpMJvo+F//uHNPuPtXnJX7iivLBP3cN1474BaePcH8BJpz/G0Ysx8FVqIK+QBMYHo44mRr6QffLP5zPDN1Ur0u7+7YLIVaCDSltMy5dUUSpqSTsbKQatzrLtAWkQw5mm45UqNfMUjAAUJGgl+YquL5MXN8v+TAkW3pQ7+QZez4W67XaYkeSU2/dt3HP9GxNDucWOHKUgvs6AVr9KGQJpWlUhYdY3hqdYorNrpgU39HaCEad44cEeZKVpp24mNyaZWyXIgaTkkhz6tif194GxK8IlJjbeVPjw1FSLLS3vWpLb48cI/28gNNBZ79V0YAwXVZ/VBPwSyz2B6/UUIq/5PVsbc3MpULVyMVQNk6OjjII01nzv/20/4pfQw1BipXC1FwOdbRife0FN+0WZoHX4ir40AusKv4OfG6PXVlaFxFYldrYKVU9sa5WF4dcixTk8qGJbv3w8JLr0GH4lOMBd1txLojCJepgBhjTnmUeZU7rua6kAUCa0eYlShFa/dtk00dSXf7ONNilJs7hsaEsjr5CDlsrhR4mKlrg+Mr/ujUNn3ZdQcNdjZwQBa7AhXmS6v+rUYGVZTWYEhxvgaA2AyZSMFcuy+dohUq21qLEbZUsMDPe5/n8NBixdYmDp5Tj1q7PKQIV99DA=='


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


