import sys

sys.path.append('/tmp')

import httpslib

def test_get():
    host = 'api.ipify.org'
    conn = httpslib.HTTPSConnection(host)
    # tell the server to close the connection. Otherwise, read() will block forever.
    headers = {'Connection': 'close'}
    conn.request("GET", "/", headers=headers)
    resp = conn.getresponse()
    print resp.status, resp.reason
    print 'headers:', resp.msg
    # You can read by chunks, e.g, resp.read(1024)
    print 'body:', resp.read()
    # This method will destroy The TLSIO Object and will also close the socket file descriptor.
    conn.shutdown()

def test_timeout():
    host = 'www.google.com'
    conn = httpslib.HTTPSConnection(host, port=81, timeout=3)
    headers = {'Connection': 'close'}
    conn.request("GET", "/", headers=headers)
    resp = conn.getresponse()
    print resp.status, resp.reason
    print 'headers:', resp.msg
    print 'body:', resp.read()
    conn.shutdown()

def test_ssl_verification():
    host = 'localhost'
    #host = 'api.ipify.org'
    conn = httpslib.HTTPSConnection(host, port=4443, timeout=10, certfile='cacert.pem')
    headers = {'Connection': 'close'}
    conn.request("GET", "/", headers=headers)
    resp = conn.getresponse()
    print resp.status, resp.reason
    print 'headers:', resp.msg
    print 'body:', resp.read()
    conn.shutdown()


test_get()
# test_timeout()
#test_ssl_verification()
