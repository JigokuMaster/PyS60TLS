import sys, os

sys.path.append('requests-0.10.0')
sys.path.append('/tmp')
sys.path.append(os.path.realpath('..'))

import requests

SERVICE = 'https://echo.free.beeceptor.com'
def test_get():

    r = requests.get(SERVICE, timeout=5)

    print "status: ", r.status_code

    print "headers: ", r.headers

    print "body: ", r.text

def test_post():

    r = requests.post(SERVICE, data={"id": 0x1}, timeout=5)

    print "status: ", r.status_code

    print "headers: ", r.headers

    print "body: ", r.text

def test_postfile():
    f = open('/tmp/test.txt', 'r')
    r = requests.post(SERVICE, files={'file': f}, timeout=5)

    print "status: ", r.status_code

    print "headers: ", r.headers

    print "body: ", r.text


def test_head():
    r = requests.head(SERVICE, timeout=5)

    print "status: ", r.status_code

    print "headers: ", r.headers

def test_auth():
    url = 'https://reqbin.com/echo'

    r = requests.get(url,auth=('utest25', '12345'), timeout=5)

    print "status: ", r.status_code

    print "headers: ", r.headers

    print "body: ", r.content



def test_timeout():
    url = 'https://www.google.com:81'

    r = requests.get(url, timeout=5)

    print "status: ", r.status_code

test_auth()
#test_postfile()
#test_head()
#test_timeout()
