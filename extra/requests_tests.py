import sys, os

sys.path.append('requests-0.10.0')
sys.path.append('/tmp')
sys.path.append(os.path.realpath('..'))

import requests

def test_get():
    url = 'https://api.ipify.org'

    r = requests.get(url, verify=True)

    print "status: ", r.status_code

def test_head():
    url = 'https://api.ipify.org'

    r = requests.head(url, verify=True)

    print "status: ", r.status_code

    print "headers: ", r.headers

def test_timeout():
    url = 'https://www.google.com:81'

    r = requests.get(url, timeout=5)

    print "status: ", r.status_code

#test_get()
#test_head()
test_timeout()