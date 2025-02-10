import configparser
import logging
import os
import re

import requests
import urllib3
from requests import session
from requests_toolbelt.utils import dump  # For debugging the HTTP request/response
from requests.auth import HTTPBasicAuth
from requests_pkcs12 import Pkcs12Adapter


def Authenticate(env, add_headers=None):
    config = configparser.RawConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read("conf/config.ini")
    # Configure the log
    log = config.get(env, "LOG")
    logging.basicConfig(
        filename=log,
        format="%(asctime)s - %(name)-8s - %(levelname)-8s - %(message)s",
        level=logging.DEBUG,  # <<--- Change  this to enable DEBUG
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # READ config.ini
    ADMIN_HOST = config.get(env, "ADMIN_HOST")
    ADMIN_PORT = config.get(env, "ADMIN_PORT")
    ADMIN_USER = config.get(env, "ADMIN_USER")
    ADMIN_PASS = config.get(env, "ADMIN_PASS")
    API_VERSION = config.get(env, "API_VERSION")
    SAML_USED = config.get(env, "SAML_USED")
    ST_AUTH = config.get(env, "ST_AUTH")
    # Here we Log in to the API
    ST_url = "https://{}:{}/api/v{}/".format(ADMIN_HOST, ADMIN_PORT, API_VERSION)
    # This is needed to ignore the untrusted certificate warning
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if ST_AUTH == "2" or ST_AUTH == "3" or ST_AUTH == "4":
        CERT_FILE = config.get(env, "CERT_FILE")
        CERT_PWD = config.get(env, "CERT_PWD")
    # Now let's create the headers
    headers = {
        "referer": ST_url + "docs/index.html",
        "cache-control": "no-cache",
        "Content-Type": "application/json",
    }
    # If SAML is used, add the header to authenticate to the ST IDP
    if SAML_USED == "True":
        headers["idp_id"] = "ST_IDP"
    if add_headers is not None:
        headers.update(add_headers)

    # Let's get the cookie, so we do not have to authenticate with each request. Here we also remove the authentication
    # from the headers because we no longer need it
    with session() as c:
        # Merge environment settings into session
        c.verify = False
        c.headers.update(headers)
        c.get(ST_url)

        try:
            if ST_AUTH == "1":
                c.auth = (ADMIN_USER, ADMIN_PASS)
                response = c.post(ST_url + "myself")
            elif ST_AUTH == "2" or ST_AUTH == "4":
                c.mount(
                    ST_url,
                    Pkcs12Adapter(pkcs12_filename=CERT_FILE, pkcs12_password=CERT_PWD),
                )  # STU
                response = c.post(ST_url + "myself")
            elif ST_AUTH == "3":
                c.auth = (ADMIN_USER, ADMIN_PASS)
                c.mount(
                    ST_url,
                    Pkcs12Adapter(pkcs12_filename=CERT_FILE, pkcs12_password=CERT_PWD),
                )  # STU
                response = c.post(ST_url + "myself")
            if response.headers["csrfToken"]:
                c.headers.update({"csrfToken": response.headers["csrfToken"]})
            response.raise_for_status()
            debug = dump.dump_response(response)
            logging.debug(debug.decode("utf-8"))
        except requests.ConnectionError as e:
            logging.error(
                "OOPS! Connection Error. You can't connect to "
                + ST_url
                + ". Find technical details below:"
            )
            logging.error(str(e))
            # print(dump.dump_response(c))
            raise SystemExit(e)
        except requests.Timeout as e:
            logging.error("OOPS!! Timeout Error")
            logging.error(str(e))
            raise SystemExit(e)
        except requests.exceptions.HTTPError as e:
            logging.error("Authentication failed")
            print(e.response.text)
            raise SystemExit(e)
        except requests.RequestException as e:
            logging.error("OOPS!! General Error")
            logging.error(str(e))
            raise SystemExit(e)
        except KeyboardInterrupt:
            logging.error("Someone interrupted the application")
        logging.info("Authentication to {} successful".format(ST_url))
    return c, ST_url


def loadOrDownload(item):
    params = {
        "limit": 25000,
    }
    resource = item + "/"
    isExist = os.path.exists("envData/{}.json".format(item))
    if not isExist:
        response = requests.get(
            url + resource,
            cookies=cookies,
            headers=headers,
            verify=False,
            params=params,
        )
        data = response.json()
        # Serializing json
        json_object = json.dumps(data, indent=4)
        # Writing to sites.json
        with open("envData/{}.json".format(item), "w") as outfile:
            outfile.write(json_object)
    else:
        with open("envData/{}.json".format(item), "r") as openfile:
            # Reading from json file
            data = json.load(openfile)
    return data


def read_secret_version(client, vault, path):
    """Read the secret version from the vault."""
    return client.secrets.kv.v2.read_secret_version(mount_point=vault, path=path)


def migrate_route_templates(s_source, source_ST, s_target, target_ST, resource):
    params = {'type': 'TEMPLATE'}
    res = s_source.get(source_ST + resource, params=params)
    routeTemplates = res.json()['result']
    for i in routeTemplates:
        checkIfExist = s_target.head(target_ST + resource + i['id'])
        if not checkIfExist.ok:
            if not i['steps']:
                response = s_target.post(target_ST + resource, json=i)
                logging.info(f"Route Template {i['name']} created, status {response.status_code}")
            else:
                logging.warning(f"LIMITATION: Cannot migrate template routes with steps, route {i['name']} omitted")
        else:
            logging.info(f"Route Template {i['name']} already exists at target")

def update_site_properties(site, metadata, data):
    """Update site properties for transfer site types."""
    if metadata:
        for k, v in metadata.items():
            site[k] = v
    if data:
        for k, v in data.items():
            site[k] = v

def update_custom_properties(site, metadata, data):
    """Update custom properties for ExternalPersistedCustomSite."""
    if metadata:
        for k, v in metadata.items():
            site['customProperties'][k] = v.replace("\n", "\\n")
    if data:
        for k, v in data.items():
            site['customProperties'][k] = v


def update_certificate(cert, keyname):
    lines = cert.splitlines(keepends=True)
    new_lines = []
    pattern = r'Content-Disposition: attachment; filename=".*"'
    text_to_add = f'keyname: {keyname}\nencoded: false'
    for line in lines:
        new_lines.append(line)
        if re.search(pattern, line):
            new_lines.append(text_to_add + '\n')
    return "".join(new_lines)

def delete_line_from_cert(cert, line_number):
    """Deletes a line from a string.

    Args:
        cert: The string to delete the line from.
        line_number: The line number to delete (1-based index).

    Returns:
        The string with the line deleted, or the original string if the
        line number is invalid.
    """
    cert_json = os.linesep.join([s for s in cert.splitlines() if s])
    lines = cert_json.splitlines()

    if 1 <= line_number <= len(lines):
        lines.pop(line_number - 1)
        return "\n".join(lines)
    else:
        return cert

def delete_headers_from_cert(cert):
    cert_json = os.linesep.join([s for s in cert.splitlines() if s])
    lines = cert_json.splitlines()
    return "\n".join(lines[2:])


