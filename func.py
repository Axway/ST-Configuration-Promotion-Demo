import configparser
import logging
import os
import re
from requests_toolbelt.multipart import decoder
from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata


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
        level=logging.INFO,  # <<--- Change  this to enable DEBUG
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


import re
import json


def process_text(cert_res):
    text = cert_res.content
    boundary_pattern = r'boundary=([a-zA-Z0-9_-]+)'

    # EXTRACT THE DIFFERENT PARTS
    match = re.search(boundary_pattern, cert_res.headers['Content-Type'])
    if not match:
        raise ValueError("Boundary not found in the text")

    boundary = ('--' + match.group(1)).encode()
    parts = text.split(boundary)

    # Loop through each part and process
    for part in parts:
        part = part.strip()  # Clean the part to avoid any leading/trailing spaces

        if not part:
            continue

        # Check if part is JSON (looking for Content-Type: application/json)
        if b"Content-Type: application/json" in part:
            try:
                json_start = part.index(b"{")  # Find the start of the JSON data
                json_end = part.rindex(b"}")  # Find the end of the JSON data
                raw_json = part[json_start:json_end + 1]
                json_data = json.loads(raw_json.decode('utf-8'))
            except Exception as e:
                print("Error decoding JSON:", e)
    public_pgp, private_pgp = extract_pgp_keys(text)
    if private_pgp:
        pgp_import = public_pgp + '\n' + private_pgp
    else:
        pgp_import = public_pgp

    return pgp_import

def extract_pgp_keys(raw_content):
    # Decode the bytes to a string
    raw_content_str = raw_content.decode('utf-8')  # assuming the content is UTF-8 encoded

    # Regular expressions to capture the public and private keys
    public_key_pattern = r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----'
    private_key_pattern = r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----'

    # Find all matches
    public_key_matches = re.findall(public_key_pattern, raw_content_str, re.DOTALL)
    private_key_matches = re.findall(private_key_pattern, raw_content_str, re.DOTALL)

    # Extract the keys
    public_key = public_key_matches[0] if public_key_matches else None
    private_key = private_key_matches[0] if private_key_matches else None

    return public_key, private_key

def parse_certificates(cert_multipart):
    multipart_data = decoder.MultipartDecoder.from_response(cert_multipart)

    for part in multipart_data.parts:
        decoded_header = part.headers[b'Content-Type'].decode('utf-8')
        if decoded_header == 'application/octet-stream':
            disposition = part.headers[b'Content-Disposition'].decode('utf-8')
            for content_info in str(disposition).split(';'):
                info = content_info.split('=', 2)
                if info[0].strip() == 'filename':
                    filename = info[1].strip('\"\'\t \r\n')
            certFile = part.content
        elif decoded_header == "application/json":
            jsonData = json.loads(part.text)
        else:
            print(decoded_header)
    keyname  = jsonData['name']
    files = {f"{keyname}": (
        certFile, 'application/octet-stream', {'keyname': f"{keyname}", 'encoded': 'false'})}
    for name, (contents, mimetype, headers) in files.items():
        rf = RequestField(name=name, data=contents, headers=headers)
        rf.make_multipart(content_disposition='attachment', content_type=mimetype)
    return jsonData, certFile, rf
