TLS extension for  PyS60.

The extension is a simple wrapper around [MbedTLS library](https://github.com/JigokuMaster/Symbian-TLS-Patch) compiled with TLS 1.2 support.

it supports certificate verification but currently only PEM format is supported for trusted certificates.
 
timeout is supported via PIPS 1.7 this runtime is required even when using the extension with PyS60 1.45

### Installation Files

see the [release](https://github.com/JigokuMaster/PyS60TLS/releases) page

PyS60TLS.zip: The libs in this archive are compiled with self-signed capabilities.


PyS60TLS_highcaps.zip: The libs in this archive have more capabilities , they can be imported and used from the scriptshell.

the archives contain the following libs :

* tls.pyd (for PyS60 1.4.5)

* kf_tls.pyd (for PyS60 2.0.0)

* httpslib.py (tls wrapper)

* requests version 0.10.0 modified to work with PyS60TLS (only for PyS60 2.0.0)

###  Usage

using httpslib.HTTPSConnection()

```python

import httpslib

host = 'github.com'

conn = httpslib.HTTPSConnection(host, timeout=5, certfile='cacert.pem')

headers = {'Connection': 'close'}

conn.request("GET", "/", headers=headers)

resp = conn.getresponse()

print resp.status, resp.reason

print 'headers dict:', resp.msg

# You can read by chunks, e.g, resp.read(1024)

print 'body:', resp.read()

# This method will destroy The TLSIO Object and will also close the socket file descriptor.

conn.shutdown()

```

using httpslib.TLSWrapper()

```python

import httpslib

# create TLSIO Object and start the handshake operation, Exception may occur here.

tls_io = httpslib.TLSWrapper(HOST_NAME, SOCKET_FD, TIMEOUT,  CERTFILE)

tls_io.write(data) # check for  Exception Error

tls_io.read(data_len[int]) # check for  Exception Error

tls_io.readAll() # check for Exception Error

tls_io.close() 

tls_io.getErrorCode() # returns error code [int]

tls_io.getError() # returns error message [str]

```

using  tls extension directly:

```python

import tls

# host_name: [str] servername.com ( without "https://" )

# socket_fd: [int] socket file descriptor , e.g, obtained using socket_object.fileno()

# on PyS60 1.4.5  "socket.fileno()"  is not implemented  tls.connect() can be used instead.

# timeout [int, optional argument] 0 for no timeout.

# certfile: [str, optional argument] path to a .pem file.


tls_io = tls.init(host_name, socket_fd,  timeout, certfile)


# start the handshake operation, 
server certificate verification will be done if the certfile was specified.
the method returns 0 on success and returns negative number on error. 

tls_io.handshake()

# Send data to the server, the method returns int value  ( negative means error) , 0 or greater means the number of written bytes

tls_io.write(data[str])

# Read data from the server

tls_io.read(data_len[int]) 

# Get the last error code,  this stored internally when calling write(), read(), start_handshake()

tls_io.getErrorCode()

# Get the last error message

tls_io.getError()
   
# destroy the io object and cleanup  MbedTLS context

tls_io.close()


# ip_address:  [str] 0.0.0.0

# port: [int] server port

# timeout: [int]

# connect to a server, on success returns the socket file descriptor 

tls.connect(ip_address, port, timeout)

```
# Notes for building

1. you need PyS60 1.4.5 and PyS60 2.0.0 SDKs.

2. download or clone the latest source code of [MbedTLS](https://github.com/JigokuMaster/Symbian-TLS-Patch)

3. clone this repo and copy the patched header pys60_headers/pyconfig.h to $EPOCROOT/epoc32/include/python

4. compile mbedtls-symbian-3.x-c90 to produce mbedtls.lib

5. compile PyS60TLS to produce tls.pyd and kf_tls.pyd


### TO-DO :
- TLS1.3 support.
