from __future__ import annotations

import abc
import json
import os
import dotenv
import requests
import urllib3
from funcsession import Authenticate
import hvac
import sys
import configparser

env = 'ST_NON_PROD'
s, url = Authenticate(env)
s.verify = False




# SETTINGS
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# VARS
vault = 'non-production'
accountName = 'DaenerysTargaryen'
accountPassword = 'JonSnow'

#HASHICORP
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

print(hashiToken)
# Authentication
client = hvac.Client(
    url=hashiHost,
    token=hashiToken,
)
print(client.is_authenticated())

# Writing a secret
create_response = client.secrets.kv.v2.create_or_update_secret(
    mount_point=vault,
    path=f'accounts/{accountName}/user',
    secret=dict(password=accountPassword),
)
print(create_response)
print('Secret written successfully.')

create_response = client.secrets.kv.v2.create_or_update_secret(
    mount_point=vault,
    path=f'accounts/{accountName}/routes',
    secret=dict(name='Don'),
)

# # Reading a secret
# read_response = client.secrets.kv.read_secret_version(mount_point='non-production', path='accounts/DaenerysTargaryen')
#
# password = read_response['data']['data']['password']
#
# print(password)
#
# print('Access granted!')
#
# RUN
resource = "accountSetup/"
s.headers.update({'Accept': 'application/json'})
res = s.get(url + resource + accountName)
allData = res.json()
#
# urlHashi = f"{hashiHost}/v1/{vault}/data/accounts/{accountName}"
# header = {"X-Vault-Token": hashiToken}
# response = requests.get(urlHashi, headers=header)
# print(response.json()['data'])
