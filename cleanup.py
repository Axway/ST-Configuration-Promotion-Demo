from funcsession import *

sess, targetST = Authenticate("ST_PROD")

resource = 'routes/'
response = sess.get(targetST + resource)
result = response.json()['result']

for r in result:
    sess.delete(targetST + resource + r['id'])

resource = 'subscriptions/'
response = sess.get(targetST + resource)
result = response.json()['result']

for r in result:
    sess.delete(targetST + resource + r['id'])

resource = 'accounts/'
response = sess.get(targetST + resource)
result = response.json()['result']

for r in result:
    res = sess.delete(targetST + resource + r['name'])
    print(res.text)