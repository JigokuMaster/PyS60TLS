#include <Python.h>
#ifdef __SYMBIAN32__
#include <symbian_python_ext_util.h>
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>


#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

#define DEBUG_LEVEL 5

static void tls_debug(void *ctx, int level,
	const char *file, int line,
	const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}
#endif

#if 0
int tls_send(void *ctx, const unsigned char *buf, size_t len)
{
    int sock_fd = *((int*)ctx);

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;


    ret = (int) send(sock_fd,(const char*)buf, len, 0);
    // printf("tcp_send(sock_fd=%d)=%d\n", sock_fd, ret);

    if (ret < 0)
    {
	/*if (net_would_block(ctx) != 0) {
	  return MBEDTLS_ERR_SSL_WANT_WRITE;
	  }*/

	if (errno == EPIPE) {
	    return MBEDTLS_ERR_NET_CONN_RESET;
	}

	if (errno == EINTR) {
	    return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}


int tls_recv(void *ctx, unsigned char *buf, size_t len)
{

    int sock_fd = *((int*)ctx);
    // printf("tcp_recv(sock_fd=%d)=%d\n", sock_fd, len);

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = (int) recv(sock_fd, (char*)buf, len, 0);

    if (ret < 0)
    {

	if (errno == EPIPE) {
	    return MBEDTLS_ERR_NET_CONN_RESET;
	}

	if (errno == EINTR) {
	    return MBEDTLS_ERR_SSL_WANT_READ;
	}

	return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;

}
#endif

class CTLS 
{

    public:
	CTLS();
	~CTLS();
	bool Init(char* hostname, int fd, uint32_t timeout);
	char* getError();
	int DoHandshake();
	int Read(unsigned char* buf, int len);
	int Write(unsigned char* data, int len);
	int Close();
    private:
	mbedtls_ssl_context ssl;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_net_context net;
	int error_code;
	char error_buf[1024];
#if defined(MBEDTLS_DEBUG_C)
	FILE* log_fp;
#endif
};


CTLS::CTLS()
{
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_net_init(&net);
    error_code = 0;
    memset(error_buf, 0, sizeof(error_buf));

}

CTLS::~CTLS()
{
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&net);
}

bool CTLS::Init(char* hostname, int fd, uint32_t timeout)
{
#if defined(MBEDTLS_DEBUG_C)
    //mbedtls_ssl_conf_dbg(conf, tls_debug, obj->log_fp);	
#endif 
    error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if(error_code != 0)
    {
	sprintf(error_buf, "mbedtls_ctr_drbg_seed() error: %d", error_code);
	return false;
    }
	
    
    error_code = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    if(error_code != 0)
    {
	sprintf(error_buf, "mbedtls_ssl_config_defaults() error: %d", error_code);
	return false;
    }
 

    //mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    // mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    error_code = mbedtls_ssl_setup(&ssl, &conf);
    if(error_code != 0)
    {
	sprintf(error_buf, "mbedtls_ssl_setup() error: %d", error_code);
	return false;
    }


    error_code = mbedtls_ssl_set_hostname(&ssl, hostname);

    if(error_code != 0)
    {
	sprintf(error_buf, "mbedtls_ssl_set_hostname() error: %d", error_code);
	return false;
    }

    net.fd = fd;
    mbedtls_ssl_conf_read_timeout(&conf, timeout);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    return true;
}

char* CTLS::getError()
{
    return (char*)error_buf;
}

int CTLS::DoHandshake()
{
    int ret = -1;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE) )
	{

	    break;
        }
    }
    return ret;

}

int CTLS::Read(unsigned char* buf, int len)
{

    int ret = 0;
    while(1)
    {
	int r = mbedtls_ssl_read(&ssl, buf, len);

        if ( (r == MBEDTLS_ERR_SSL_WANT_READ) || (r == MBEDTLS_ERR_SSL_WANT_WRITE) )
	{
            continue;
        }

	if(r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
	{
	    r = 0;
	}
	ret = r;	
	break;
    }
    return ret;
}

int CTLS::Write(unsigned char* data, int len)
{

    int ret = 0;
    while((ret = mbedtls_ssl_write(&ssl, data, len)) <= 0)
    {

        if ( (ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE) )
	{
            break;
        }
    }
    return ret;
}

int CTLS::Close()
{
    return mbedtls_ssl_close_notify(&ssl);
}

struct TLS_object 
{
    PyObject_VAR_HEAD
    CTLS* tls;
    int error_code;
};

#ifdef __SYMBIAN32__
#define TLS_type ((PyTypeObject*)SPyGetGlobalString("TLSType"))
#endif

extern "C" PyObject* tls_handshake_start(TLS_object* obj, PyObject* args)
{


    int ret = 0;
    Py_BEGIN_ALLOW_THREADS
    ret = obj->tls->DoHandshake();
    Py_END_ALLOW_THREADS
    obj->error_code = ret;
    return Py_BuildValue("i", ret);
}

extern "C" PyObject* tls_read(TLS_object* obj, PyObject* args)
{

    int ret = 0;
    const int min_read = 1024;
    int len = min_read;
    PyObject* buf;
    if (!PyArg_ParseTuple(args, "|i", &len))
    {
        return NULL;
    }

    if(len <= 0)
    {
	len = min_read;
    }

    if(!(buf = PyString_FromStringAndSize((char*)0, len)) )
    {
	return NULL;
    }


    Py_BEGIN_ALLOW_THREADS
    ret = obj->tls->Read((unsigned char*)PyString_AsString(buf), len);
    Py_END_ALLOW_THREADS
    if(ret >= 0)
    {
	if((ret != len) && _PyString_Resize(&buf, ret) < 0)
    
	{
	    return NULL;
	}
    }

    obj->error_code = (ret < 0) ? ret : 0;
    return buf;
}


extern "C" PyObject* tls_write(TLS_object* obj, PyObject* args)
{


    unsigned char* data;
    int len, ret;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
    {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    ret = obj->tls->Write(data, len);
    Py_END_ALLOW_THREADS
    obj->error_code = ret;
    return Py_BuildValue("i", ret);
}



extern "C" PyObject* tls_close(TLS_object* obj, PyObject* args)
{

    int ret = obj->tls->Close();
    obj->error_code = ret;
    return Py_BuildValue("i", ret);
}

extern "C" PyObject* tls_geterror(TLS_object* obj, PyObject* args)
{
    return Py_BuildValue("i",obj->error_code);
}



const static PyMethodDef tls_object_methods[] = 
{
    {"handshake", (PyCFunction)tls_handshake_start, METH_VARARGS},
    {"read", (PyCFunction)tls_read, METH_VARARGS},
    {"write", (PyCFunction)tls_write, METH_VARARGS},
    {"close", (PyCFunction)tls_close, METH_NOARGS},
    {"getError", (PyCFunction)tls_geterror, METH_NOARGS},
    {NULL, NULL}           // sentinel

};



static void tls_dealloc(TLS_object *obj)
{
    if(obj->tls != NULL)
    {
	delete obj->tls;
	obj->tls = NULL;
    }
    PyObject_Del(obj);
}


static PyObject * tls_getattr(TLS_object  *op, char *name)
{
    return Py_FindMethod((PyMethodDef*)tls_object_methods, (PyObject *)op, name);
}
  


static int tls_setattr(TLS_object *op, char *name, PyObject *v)
{
    return 0;
}

static PyTypeObject c_tls_type = 
{

    PyObject_HEAD_INIT(NULL)
    0,                                         /*ob_size*/
    "tls.TLSIO",                             /*tp_name*/
    sizeof(TLS_object),                     /*tp_basicsize*/
    0,                                         /*tp_itemsize*/
    /* methods */
    (destructor)tls_dealloc,                /*tp_dealloc*/
    0,                                         /*tp_print*/
    (getattrfunc)tls_getattr,               /*tp_getattr*/
    (setattrfunc)tls_setattr,               /*tp_setattr*/
    0,                                         /*tp_compare*/
    0,                                         /*tp_repr*/
    0,                                         /*tp_as_number*/
    0,                                         /*tp_as_sequence*/
    0,                                         /*tp_as_mapping*/
    0,                                         /*tp_hash*/

};



extern "C" PyObject* tls_init(PyObject* /*self*/, PyObject* args)
{

    char* server_name;
    int socket_fd;
    uint32_t timeout = 0;
    char* cert_file = NULL;
    if (!PyArg_ParseTuple(args, "si|is",&server_name, &socket_fd, &timeout, &cert_file))
    {
	return NULL;
    }
    TLS_object *obj;

#ifdef __SYMBIAN32__ 
    if (!(obj = PyObject_New(TLS_object, TLS_type)))
    {
      return PyErr_NoMemory();
    }
#else
    if (!(obj = PyObject_New(TLS_object, &c_tls_type)))
    {
      return PyErr_NoMemory();
    }
#endif

    obj->error_code = 0;
    if (!(obj->tls = new CTLS()) )
    {
	return PyErr_NoMemory();
    }

    if(!obj->tls->Init(server_name, socket_fd, timeout))
    {
	return PyErr_Format(PyExc_SystemError, obj->tls->getError());
    }
    return (PyObject*)obj;
}



extern "C" PyObject* tls_connect(PyObject*, PyObject* args)
{

    char* server_name;
    int server_port;
    if (!PyArg_ParseTuple(args, "si",&server_name, &server_port))
    {
	return NULL;
    }
    
    int socket_fd = -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    if(inet_aton(server_name, &addr.sin_addr) < 1)
    {
		PyErr_SetString(PyExc_SystemError, "invalid IP address");
		return NULL;
    }


    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) > 0)
    {
	if(connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		close(socket_fd);
		return PyErr_SetFromErrno(PyExc_IOError);
	}
    }


    return Py_BuildValue("i", socket_fd);

}

const static PyMethodDef tls_methods[] = 
{

    {"init", (PyCFunction)tls_init, METH_VARARGS},
    {"connect", (PyCFunction)tls_connect, METH_VARARGS},
    {NULL, NULL}           // sentinel

};


extern "C"
{

#define DEFTYPE(name,type_template)  do {				\
    PyTypeObject* tmp = PyObject_New(PyTypeObject, &PyType_Type);	\
    *tmp = (type_template);						\
    tmp->ob_type = &PyType_Type;					\
    SPyAddGlobalString((name), (PyObject*)tmp);				\
  } while (0)
  

    // first exported function
    DL_EXPORT(void) inittls(void)
    {

	#ifdef __SYMBIAN32__
	DEFTYPE("TLSType",c_tls_type);
	#endif 
	PyObject* m = Py_InitModule("tls", (PyMethodDef*)tls_methods);
	PyModule_AddIntConstant(m,"MBEDTLS_ERR_SSL_TIMEOUT", MBEDTLS_ERR_SSL_TIMEOUT);
    }

    // second exported function
    DL_EXPORT(void) ixfinitls(void*)
    {
		/*
		*
		* this function will be called by SPy_dynload_finalize()
		*
		* if we don't export it here,a wrong function exported by mbetls will be called instead !!!
		*
		*/
	}

}






