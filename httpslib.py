from httplib import HTTPConnection, HTTPS_PORT
import socket, os, tls

USE_TLS_CONNECT = False
HAVE_SOCKET_TIMEOUT = hasattr(socket, 'setdefaulttimeout') and hasattr(socket, 'timeout') 
try:
    import e32
    USE_TLS_CONNECT = e32.pys60_version_info[:3] == (1, 4, 5)
except:
    USE_TLS_CONNECT = not HAVE_SOCKET_TIMEOUT

# auto-generated from mbedtls headers.

MBEDTLS_ERRORS_MAP = {
	-0x7000: 'MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS',
	-0x7080: 'MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE',
	-0x7100: 'MBEDTLS_ERR_SSL_BAD_INPUT_DATA',
	-0x7180: 'MBEDTLS_ERR_SSL_INVALID_MAC',
	-0x7200: 'MBEDTLS_ERR_SSL_INVALID_RECORD',
	-0x7280: 'MBEDTLS_ERR_SSL_CONN_EOF',
	-0x7300: 'MBEDTLS_ERR_SSL_DECODE_ERROR',
	-0x7400: 'MBEDTLS_ERR_SSL_NO_RNG',
	-0x7480: 'MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE',
	-0x7500: 'MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION',
	-0x7580: 'MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL',
	-0x7600: 'MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED',
	-0x7680: 'MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED',
	-0x7700: 'MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE',
	-0x7780: 'MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE',
	-0x7800: 'MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME',
	-0x7880: 'MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY',
	-0x7A00: 'MBEDTLS_ERR_SSL_BAD_CERTIFICATE',
	-0x7B00: 'MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET',
	-0x7B80: 'MBEDTLS_ERR_SSL_CANNOT_READ_EARLY_DATA',
	-0x7C00: 'MBEDTLS_ERR_SSL_CANNOT_WRITE_EARLY_DATA',
	-0x7F00: 'MBEDTLS_ERR_SSL_ALLOC_FAILED',
	-0x7F80: 'MBEDTLS_ERR_SSL_HW_ACCEL_FAILED',
	-0x6F80: 'MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH',
	-0x6E80: 'MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION',
	-0x6E00: 'MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE',
	-0x6D80: 'MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED',
	-0x6D00: 'MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH',
	-0x6C80: 'MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY',
	-0x6C00: 'MBEDTLS_ERR_SSL_INTERNAL_ERROR',
	-0x6B80: 'MBEDTLS_ERR_SSL_COUNTER_WRAPPING',
	-0x6B00: 'MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO',
	-0x6A80: 'MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED',
	-0x6A00: 'MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL',
	-0x6900: 'MBEDTLS_ERR_SSL_WANT_READ',
	-0x6880: 'MBEDTLS_ERR_SSL_WANT_WRITE',
	-0x6800: 'MBEDTLS_ERR_SSL_TIMEOUT',
	-0x6780: 'MBEDTLS_ERR_SSL_CLIENT_RECONNECT',
	-0x6700: 'MBEDTLS_ERR_SSL_UNEXPECTED_RECORD',
	-0x6680: 'MBEDTLS_ERR_SSL_NON_FATAL',
	-0x6600: 'MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER',
	-0x6580: 'MBEDTLS_ERR_SSL_CONTINUE_PROCESSING',
	-0x6500: 'MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS',
	-0x6480: 'MBEDTLS_ERR_SSL_EARLY_MESSAGE',
	-0x6000: 'MBEDTLS_ERR_SSL_UNEXPECTED_CID',
	-0x5F00: 'MBEDTLS_ERR_SSL_VERSION_MISMATCH',
	-0x5E80: 'MBEDTLS_ERR_SSL_BAD_CONFIG',
	10: 'MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE',
	20: 'MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC',
	21: 'MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED',
	22: 'MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW',
	30: 'MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE',
	40: 'MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE',
	41: 'MBEDTLS_SSL_ALERT_MSG_NO_CERT',
	42: 'MBEDTLS_SSL_ALERT_MSG_BAD_CERT',
	43: 'MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT',
	44: 'MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED',
	45: 'MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED',
	46: 'MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN',
	47: 'MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER',
	48: 'MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA',
	49: 'MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED',
	50: 'MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR',
	51: 'MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR',
	60: 'MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION',
	70: 'MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION',
	71: 'MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY',
	80: 'MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR',
	86: 'MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK',
	90: 'MBEDTLS_SSL_ALERT_MSG_USER_CANCELED',
	100: 'MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION',
	109: 'MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION',
	110: 'MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT',
	112: 'MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME',
	115: 'MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY',
	116: 'MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED',
	120: 'MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL',
	-0x2080: 'MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE',
	-0x2100: 'MBEDTLS_ERR_X509_UNKNOWN_OID',
	-0x2180: 'MBEDTLS_ERR_X509_INVALID_FORMAT',
	-0x2200: 'MBEDTLS_ERR_X509_INVALID_VERSION',
	-0x2280: 'MBEDTLS_ERR_X509_INVALID_SERIAL',
	-0x2300: 'MBEDTLS_ERR_X509_INVALID_ALG',
	-0x2380: 'MBEDTLS_ERR_X509_INVALID_NAME',
	-0x2400: 'MBEDTLS_ERR_X509_INVALID_DATE',
	-0x2480: 'MBEDTLS_ERR_X509_INVALID_SIGNATURE',
	-0x2500: 'MBEDTLS_ERR_X509_INVALID_EXTENSIONS',
	-0x2580: 'MBEDTLS_ERR_X509_UNKNOWN_VERSION',
	-0x2600: 'MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG',
	-0x2680: 'MBEDTLS_ERR_X509_SIG_MISMATCH',
	-0x2700: 'MBEDTLS_ERR_X509_CERT_VERIFY_FAILED',
	-0x2780: 'MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT',
	-0x2800: 'MBEDTLS_ERR_X509_BAD_INPUT_DATA',
	-0x2880: 'MBEDTLS_ERR_X509_ALLOC_FAILED',
	-0x2900: 'MBEDTLS_ERR_X509_FILE_IO_ERROR',
	-0x2980: 'MBEDTLS_ERR_X509_BUFFER_TOO_SMALL',
	-0x3000: 'MBEDTLS_ERR_X509_FATAL_ERROR',
	0x01: 'MBEDTLS_X509_BADCERT_EXPIRED',
	0x02: 'MBEDTLS_X509_BADCERT_REVOKED',
	0x04: 'MBEDTLS_X509_BADCERT_CN_MISMATCH',
	0x08: 'MBEDTLS_X509_BADCERT_NOT_TRUSTED',
	0x10: 'MBEDTLS_X509_BADCRL_NOT_TRUSTED',
	0x20: 'MBEDTLS_X509_BADCRL_EXPIRED',
	0x40: 'MBEDTLS_X509_BADCERT_MISSING',
	0x80: 'MBEDTLS_X509_BADCERT_SKIP_VERIFY',
	0x0100: 'MBEDTLS_X509_BADCERT_OTHER',
	0x0200: 'MBEDTLS_X509_BADCERT_FUTURE',
	0x0400: 'MBEDTLS_X509_BADCRL_FUTURE',
	0x0800: 'MBEDTLS_X509_BADCERT_KEY_USAGE',
	0x1000: 'MBEDTLS_X509_BADCERT_EXT_KEY_USAGE',
	0x2000: 'MBEDTLS_X509_BADCERT_NS_CERT_TYPE',
	0x4000: 'MBEDTLS_X509_BADCERT_BAD_MD',
	0x8000: 'MBEDTLS_X509_BADCERT_BAD_PK',
	0x010000: 'MBEDTLS_X509_BADCERT_BAD_KEY',
	0x020000: 'MBEDTLS_X509_BADCRL_BAD_MD',
	0x040000: 'MBEDTLS_X509_BADCRL_BAD_PK',
	0x080000: 'MBEDTLS_X509_BADCRL_BAD_KEY'
}


class TLSWrapper:
    def __init__(self, addr, socket_fd, timeout=None, certfile=None):
        self.timeout = timeout
        self.cert_file = certfile
        self.init_tls(addr, socket_fd)

    def _throwException(self, msg, err_code):
        if self.timeout and (err_code == tls.MBEDTLS_ERR_SSL_TIMEOUT):
            msg = "Connection timed out"
            if HAVE_SOCKET_TIMEOUT:
                raise socket.timeout(msg)
            else:
                raise tls.TLSError(msg)

        str_ec = None
        if err_code in MBEDTLS_ERRORS_MAP:
            str_ec = MBEDTLS_ERRORS_MAP[err_code]
        elif abs(err_code) in MBEDTLS_ERRORS_MAP:
            str_ec = MBEDTLS_ERRORS_MAP[abs(err_code)]
        else:
            str_ec = str(err_code)
        if str_ec:
            msg += ' [%s]' %str_ec  
        raise tls.TLSError(msg)

    def close(self):
        self.tls_obj.close()

    def init_tls(self, addr, socket_fd):
        self.tls_obj = tls.init(addr, socket_fd, self.timeout, self.cert_file)
        err = self.tls_obj.handshake()
        if err != 0:
            self.close()
            msg = 'tls.handshake() %s' %self.getError()
            self._throwException(msg, err)

    def write(self, data):
        r = self.tls_obj.write(data)
        if r <= 0:
            self.close()
            msg = 'tls.write() %s' %self.getError()
            self._throwException(msg, r)
        return r 
    
    def readAll(self):
        data = []
        while True:
            data.append(self.tls_obj.read())
            r = self.tls_obj.getErrorCode()
            if r < 0:
                self.close()
                msg = 'tls.read() %s' %self.getError()
                self._throwException(msg, r)

            if r == 0: #EOF
                break
        return ''.join(data)
 
    def read(self, rlen=-1):
        # print 'TLSWrapper.read(%s)' %rlen
        if rlen < 1:
            return self.readAll()
        else:
            data = self.tls_obj.read(rlen)
            r = self.tls_obj.getErrorCode()
            if r < 0:
                self.close()
                msg = 'tls.read() %s' %self.getError()
                self._throwException(msg, r)
            else:
                return data

    def getErrorCode(self):
        return self.tls_obj.getErrorCode()

    def getError(self):
        return self.tls_obj.getError()

    def settimeout(self, timeout=0):
        self.timeout = timeout

class TLSFile:

    BUFSIZE = 8192

    def __init__(self, sock, bufsize=None):
        self.sock = sock
        self._buf = ''
        self._bufsize = bufsize or self.__class__.BUFSIZE

    def close(self):
        pass

    def read(self, size=-1):
        return self.sock.recv(size)

    def write(self, data):
        return self.sock.send(data)


    def readline(self):
        L = [self._buf]
        self._buf = ''
        while 1:
            i = L[-1].find("\n")
            if i >= 0:
                break
            s = self.read(1)
            if s == '':
                break
            L.append(s)
        if i == -1:
            return "".join(L)
        else:
            all = "".join(L)
            i = all.find("\n") + 1
            line = all[:i]
            self._buf = all[i:]
            return line

class TLSSocket:
    def __init__(self, host, port, sock, sock_fd, timeout=None, certfile=None):
        self.io_closed = False
        self.sock = sock
        self.sock_fd = sock_fd
        self.timeout = timeout
        self._tls = TLSWrapper(host, sock_fd, timeout, certfile)


    def close_io(self):
        if self.sock != None:
            self.sock.close()
        else:
            os.close(self.sock_fd)
            
        if self._tls:
            self._tls.close()
        self.io_closed = True

    def __del__(self):
        if not self.io_closed:
            try:
                self.close_io()
            except:pass    

    def close(self):
        pass

    def makefile(self, mode, bufsize=None):
        return TLSFile(self, bufsize)

    def send(self, stuff, flags = 0):
        return self._tls.write(stuff)

    sendall = send

    def recv(self, rlen = 1024, flags = 0):
        return self._tls.read(rlen)

    def settimeout(self, timeout=0):
        self.timeout = timeout
        if self.sock and HAVE_SOCKET_TIMEOUT:
            self.sock.settimeout(timeout)

        if self._tls:
            self._tls.settimeout(timeout)

class HTTPSConnection(HTTPConnection):

    default_port = HTTPS_PORT

    def __init__(self, host, port=None, timeout=None, certfile=None):
        HTTPConnection.__init__(self, host, port)
        self.cert_file = certfile
        self.timeout = timeout
        self.tls_verify = True


    def _settimeout(self, sock, timeout):
        if timeout and HAVE_SOCKET_TIMEOUT:
            sock.settimeout(timeout)

    def connect(self):
        sock = None
        sock_fd = -1
        if USE_TLS_CONNECT:
            ip_addr =  socket.gethostbyname(self.host)
            sock_fd = tls.connect(ip_addr, self.port, self.timeout)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._settimeout(sock, self.timeout)
            sock.connect((self.host, self.port))
            sock.setblocking(1)
            sock_fd = sock.fileno()

        certfile = self.cert_file
        # print 'certfile: ', certfile
        # print 'tls_verify: ', self.tls_verify 
        if not self.tls_verify:
            cert_file = None

        self.sock = TLSSocket(self.host, self.port, sock, sock_fd, self.timeout, certfile)

    def shutdown(self):
        if self.sock:
            try:
                self.sock.close_io()
            except:pass    
        self.close()
            
