TLS extension for  PyS60.

The extension uses [MbedTLS](https://github.com/JigokuMaster/Symbian-TLS-Patch) compiled with TLS2.0 support.

### Installation Files

see the [release](https://github.com/JigokuMaster/PyS60TLS/releases) page

PyS60TLS_SS.zip: The libs in this archive are compiled with self-signed capabilities


* tls.pyd (for PyS60 1.4.5)

* kf_tls.pyd (for PyS60 2.0.0)

* mbedtls341_stl.dll (required by the pyd extensions)

* httpslib.py (helper classes)

PyS60TLS_highcaps.zip: The libs in this archive have more capabilities , they can be imported and used from the scriptshell.

PyS60TLS.zip: The libs in this archive are statically linked with Mbedtls library. no need to include mbedtls341_stl.dll

ipify.SISX: simple app to show public ip address (requires PyS60 1.4.5)

###  Usage

using httpslib.HTTPSConnection()

```python

import httpslib

host = 'github.com'

conn = httpslib.HTTPSConnection(host)

# tell the server to close the connection. Otherwise, read() will block forever.

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

tls_io = httpslib.TLSWrapper(HOST_NAME, SOCKET_FD)

tls_io.write(data) # check for  Exception Error

tls_io.read(data_len[int]) # check for  Exception Error

tls_io.readAll() # check for Exception Error

tls_io.close() 

tls_io.getError() # returns error code [int]

```

using  tls extension directly:

```python

import tls

# HOST_NAME :  [str] servername.com ( without "https://" )

# SOCKET_FD = [int] socket file descriptor , e.g, obtained using socket_object.fileno() , 

# on PyS60 1.4 5  "socket.fileno()"  is not implemented  , tls.connect() can be used instead.

# CERT_FILE = [str, optional argument] unused because server verification isn't implemented for now.

tls_io = tls.init(HOST_NAME, SOCKET_FD, PORT, CERT_FILE)


# start the handshake operation, the method returns 0 on success and returns negative number on error.

tls_io.start_handshake()

# Send data to the server, the method returns int value  ( negative means error) , 0 or greater means the number of written bytes

tls_io.write(data[str])

# Read data from the server

tls_io.read(data_len[int]) 

# Gets the error code,  this stored internally when calling write(), read(), start_handshake()

tls_io.getError()

# destroy the io object and cleanup  MbedTLS context

tls_io.close()


# IP_ADDRESS :  [str] 0.0.0.0

# PORT =  [int] server port

# connect to a server, on success returns the socket file descriptor 

tls.connect(IP_ADDRESS, PORT)

```

### TO-DO :
- timeout support.
- server verification.
- TLS1.3 support.