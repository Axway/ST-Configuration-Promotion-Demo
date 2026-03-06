# This is provided as-is, and you should run it at your own risk.
# Promotes composite & simple routes (with their subscriptions) for a given account
# from a source ST to a target ST.
import sys
import os
import warnings
import copy
import logging
import dotenv
from func import *
import hvac

# SETTINGS
warnings.filterwarnings("ignore", category=DeprecationWarning)
dotenv_path = ".env"
dotenv.load_dotenv(dotenv_path)
hashiToken = os.environ.get("VAULT_TOKEN")
hashiHost = os.environ.get("VAULT_HOST")

# Clear log file so only current run is visible
open('Logs/master.log', 'w').close()

# Authenticate with ST
s_source, source_ST = Authenticate(os.environ.get("ST_SOURCE", "ST_NON_PROD"))
s_source.verify = False
s_source.headers.update({'Accept': 'application/json'})
s_target, target_ST = Authenticate(os.environ.get("ST_TARGET", "ST_PROD"))
s_target.verify = False
s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})

# Hashi Authentication
vault = 'SecureTransport'
tier = 'production'
client = hvac.Client(url=hashiHost, token=hashiToken, verify=False)

accountsToMigrate = [os.environ.get("ACCOUNT_NAME", "hrisy")]

has_errors = False
resource = 'routes/'

# ── Migrate route templates first ──────────────────────────────────────────
migrate_route_templates(s_source, source_ST, s_target, target_ST, resource)

for account in accountsToMigrate:
    logging.info(f"Starting route promotion for account '{account}'")

    # Verify the account exists on the target
    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    acct_check = s_target.get(target_ST + 'accounts/' + account)
    if not acct_check.ok:
        msg = f"Account '{account}' does not exist on target — cannot promote routes"
        logging.error(msg)
        print(f"ERROR: {msg}")
        has_errors = True
        continue

    # ── Fetch routes from the source via accountSetup ──────────────────────
    s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    res = s_source.get(source_ST + 'accountSetup/' + account)
    if not res.ok:
        msg = f"Could not fetch accountSetup for account '{account}' from source: {res.status_code}"
        logging.error(msg)
        print(f"ERROR: {msg}")
        has_errors = True
        continue

    accountSetup = res.json()
    compositeRoutes = copy.deepcopy(accountSetup['accountSetup']['routes'])
    subscriptions = copy.deepcopy(accountSetup['accountSetup']['subscriptions'])

    # Filter to a specific route if ROUTE_NAME is set
    route_name_filter = os.environ.get("ROUTE_NAME", "").strip()
    if route_name_filter:
        compositeRoutes = [r for r in compositeRoutes if r['name'] == route_name_filter]
        if not compositeRoutes:
            msg = f"Route '{route_name_filter}' not found in source account '{account}'"
            logging.error(msg)
            print(f"ERROR: {msg}")
            has_errors = True
            continue

    src_routes = len(compositeRoutes)
    created_routes = 0
    updated_routes = 0
    created_subs = 0

    # ── Get existing routes on target ─────────────────────────────────────
    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    tgt_routes_res = s_target.get(target_ST + resource,
                                  params={'account': account, 'type': 'COMPOSITE', 'limit': 200})
    existing_route_names = set()
    if tgt_routes_res.ok:
        for r in tgt_routes_res.json().get('result', []):
            existing_route_names.add(r.get('name'))

    # ── Create missing composite routes on target ─────────────────────────
    for route in compositeRoutes:
        route_name = route['name']

        if route_name not in existing_route_names:
            # Create the composite route (without subscriptions/steps initially)
            route_copy = copy.deepcopy(route)
            route_copy.pop('id', None)
            route_copy['subscriptions'] = []
            for step in route_copy.get('steps', []):
                step.pop('id', None)
                step.pop('metadata', None)
                # Remove executeRoute references — will be patched later
                step.pop('executeRoute', None)
            # Remove ExecuteRoute steps for initial creation
            route_copy['steps'] = [s for s in route_copy['steps'] if s.get('type') != 'ExecuteRoute']

            s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            create_resp = s_target.post(target_ST + resource, json=route_copy)
            if create_resp.ok:
                created_routes += 1
                logging.info(f"Created composite route '{route_name}'")
            else:
                logging.warning(f"Failed to create composite route '{route_name}': {create_resp.status_code}, {create_resp.text}")
                print(f"WARNING: Failed to create composite route '{route_name}': {create_resp.text}")

    # ── Update composite routes: subscriptions + ExecuteRoute steps ────────
    for c_route in compositeRoutes:
        route_name = c_route['name']
        s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
        getRouteID = s_target.get(target_ST + resource,
                                  params=dict(fields='id,steps', account=account,
                                              type='COMPOSITE', name=route_name))
        route_result = getRouteID.json().get('result', [])
        if not route_result:
            logging.warning(f"Composite route '{route_name}' not found on target — skipping")
            continue

        new_c_route_id = route_result[0]['id']
        executeRoute = False
        if route_result[0].get('steps') and 'executeRoute' in route_result[0]['steps'][0]:
            executeRoute = True

        # ── Assign subscriptions ──────────────────────────────────────────
        if c_route['subscriptions']:
            newSubscriptions = []
            for sub in c_route['subscriptions']:
                sub_resource = 'subscriptions/'
                s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                result = s_source.get(source_ST + sub_resource + sub)
                if not result.ok:
                    logging.warning(f"Could not fetch subscription '{sub}' from source")
                    continue
                source_sub = result.json()

                s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                checkIfExists = s_target.get(target_ST + sub_resource,
                                             params={'account': account, 'folder': source_sub['folder']})
                checkIfExistsResult = checkIfExists.json()
                if checkIfExistsResult['resultSet']['totalCount'] == 0:
                    for transferConf in source_sub['transferConfigurations']:
                        transferConf.pop('id', None)
                    # Ensure the application exists on the target
                    app_name = source_sub.get('application')
                    if app_name:
                        app_head = s_target.head(target_ST + 'applications/' + app_name)
                        if app_head.status_code == 404:
                            s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                            src_app_res = s_source.get(source_ST + 'applications/' + app_name)
                            if src_app_res.ok:
                                app_body = src_app_res.json()
                                app_body.pop('id', None)
                                app_create = s_target.post(target_ST + 'applications/', json=app_body)
                                if app_create.ok:
                                    logging.info(f"Created application '{app_name}' on target")
                                elif 'already exists' in app_create.text:
                                    logging.info(f"Application '{app_name}' already exists on target")
                                else:
                                    logging.warning(f"Failed to create application '{app_name}': {app_create.text}")
                                    continue
                            else:
                                logging.warning(f"Could not fetch application '{app_name}' from source")
                                continue

                    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                    source_sub.pop('id', None)
                    create = s_target.post(target_ST + sub_resource, json=source_sub)
                    if create.ok:
                        subscriptionID = create.headers['Location'].rsplit('/', 1)[-1]
                        newSubscriptions.append(subscriptionID)
                        created_subs += 1
                        logging.info(f"Created subscription for folder '{source_sub['folder']}'")
                    else:
                        logging.warning(f"Subscription create failed: {create.status_code}, {create.text}")
                else:
                    subscriptionID = checkIfExistsResult['result'][0]['id']
                    newSubscriptions.append(subscriptionID)

            # Patch subscriptions onto the composite route
            if newSubscriptions:
                payload = [{"op": "replace", "path": "/subscriptions", "value": newSubscriptions}]
                s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                response = s_target.patch(target_ST + resource + new_c_route_id, json=payload)
                if response.ok:
                    logging.info(f"Patched subscriptions on route '{route_name}': {response.status_code}")
                else:
                    logging.warning(f"Failed to patch subscriptions on route '{route_name}': {response.text}")

        # ── Handle ExecuteRoute steps (simple routes) ─────────────────────
        if c_route['steps'] and c_route['steps'][0]['type'] == 'ExecuteRoute' and not executeRoute:
            s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            resp = s_source.get(c_route['steps'][0]['metadata']['links']['executeRoute'])
            if not resp.ok:
                logging.warning(f"Could not fetch simple route for '{route_name}' from source")
                continue
            simpleRouteName = resp.json()['name']

            s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            checkIfSimpleRouteExists = s_target.get(target_ST + resource,
                                                    params=dict(type='SIMPLE', name=simpleRouteName))
            if checkIfSimpleRouteExists.json()['resultSet']['totalCount'] > 0:
                simpleRouteID = checkIfSimpleRouteExists.json()['result'][0]['id']
                logging.info(f"Simple route '{simpleRouteName}' already exists on target")
            else:
                # Create the simple route from source
                for step in c_route['steps']:
                    if step['type'] != 'ExecuteRoute':
                        continue
                    metadataURI = step['metadata']['links']['executeRoute']
                    s_source.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                    result = s_source.get(metadataURI)
                    if not result.ok:
                        logging.warning(f"Could not fetch simple route from source: {result.text}")
                        continue
                    data = result.json()
                    data.pop('id', None)
                    for r_step in data.get('steps', []):
                        r_step.pop('precedingStep', None)
                        r_step.pop('id', None)

                    s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
                    create = s_target.post(target_ST + resource, json=data)
                    if create.ok:
                        created_routes += 1
                        simpleRouteID = create.headers['Location'].rsplit('/', 1)[-1]
                        logging.info(f"Created simple route '{simpleRouteName}'")
                    else:
                        logging.warning(f"Failed to create simple route '{simpleRouteName}': {create.text}")
                        print(f"WARNING: Failed to create simple route '{simpleRouteName}': {create.text}")
                        continue

            # Patch the ExecuteRoute step onto the composite route
            step_data = copy.deepcopy(c_route['steps'][0])
            step_data.pop('id', None)
            step_data.pop('metadata', None)
            step_data['executeRoute'] = simpleRouteID
            payload = [{"op": "replace", "path": "/steps", "value": [step_data]}]
            s_target.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            response = s_target.patch(target_ST + resource + new_c_route_id, json=payload)
            if response.ok:
                updated_routes += 1
                logging.info(f"Patched ExecuteRoute step on route '{route_name}'")
            else:
                logging.warning(f"Failed to patch ExecuteRoute step on route '{route_name}': {response.text}")

    # ── Summary ───────────────────────────────────────────────────────────
    summary = (
        f"\n{'─' * 54}\n"
        f"  Route promotion summary for account: {account}\n"
        f"{'─' * 54}\n"
        f"  {'Item':<25} {'Source':>8}   {'Target':>12}\n"
        f"  {'─' * 48}\n"
        f"  {'Composite routes':<25} {src_routes:>8}   {created_routes:>12} created\n"
        f"  {'Routes updated':<25} {'':>8}   {updated_routes:>12} patched\n"
        f"  {'Subscriptions':<25} {'':>8}   {created_subs:>12} created\n"
        f"{'─' * 54}"
    )
    print(summary)
    logging.info(summary)

if has_errors:
    sys.exit(1)

