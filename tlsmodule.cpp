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



struct TLS_object {
  PyObject_VAR_HEAD
  mbedtls_ssl_context* ctx;
  mbedtls_ctr_drbg_context* ctr_drbg;
  mbedtls_ssl_config* conf;
  mbedtls_entropy_context* entropy;
  int socket_fd;
  int error_code;
#if defined(MBEDTLS_DEBUG_C)
  FILE* log_fp;
#endif
};

#ifdef __SYMBIAN32__
#define TLS_type ((PyTypeObject*)SPyGetGlobalString("TLSType"))
#endif

extern "C" PyObject* tls_handshake_start(TLS_object* tlsobj, PyObject* args)
{


    int ret = -1;
    Py_BEGIN_ALLOW_THREADS
    while ((ret = mbedtls_ssl_handshake(tlsobj->ctx)) != 0)
    {
        if((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE) )
	{

	    break;
        }
    }

    Py_END_ALLOW_THREADS
    tlsobj->error_code = ret;
    return Py_BuildValue("i", ret);
}

extern "C" PyObject* tls_read(TLS_object* tlsobj, PyObject* args)
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

    while(1)
    {
	int r = mbedtls_ssl_read(tlsobj->ctx, (unsigned char*)PyString_AsString(buf), len);

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

    Py_END_ALLOW_THREADS
    if(ret >= 0)
    {
	if((ret != len) && _PyString_Resize(&buf, ret) < 0)
    
	{
	    return NULL;
	}
    }

    tlsobj->error_code = (ret < 0) ? ret : 0;
    return buf;
}


extern "C" PyObject* tls_write(TLS_object* tlsobj, PyObject* args)
{


    unsigned char* data;
    int len, ret;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
    {
        return NULL;
    }


    Py_BEGIN_ALLOW_THREADS
    while((ret = mbedtls_ssl_write(tlsobj->ctx, data, len)) <= 0)
    {

        if ( (ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE) )
	{
            break;
        }
    }
    Py_END_ALLOW_THREADS

    tlsobj->error_code = ret;

    return Py_BuildValue("i", ret);

}



extern "C" PyObject* tls_close(TLS_object* tlsobj, PyObject* args)
{
    /*if(tlsobj->socket_fd > 0)  
    {
	close(tlsobj->socket_fd);
    }*/

    int ret = mbedtls_ssl_close_notify(tlsobj->ctx);
    tlsobj->error_code = ret;
    return Py_BuildValue("i", ret);

}

extern "C" PyObject* tls_geterror(TLS_object* tlsobj, PyObject* args)
{

    return Py_BuildValue("i", tlsobj->error_code);
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
    if(obj->ctx != NULL)
	{
		mbedtls_ssl_free(obj->ctx);
		obj->ctx = NULL;
	}
	if(obj->conf != NULL)
    {
		mbedtls_ssl_config_free(obj->conf);
		obj->conf = NULL;
	}	
    if(obj->ctr_drbg != NULL)
	{
		mbedtls_ctr_drbg_free(obj->ctr_drbg);
		obj->ctr_drbg = NULL;
	}
	if(obj->entropy != NULL)
    {
		mbedtls_entropy_free(obj->entropy);
		obj->entropy = NULL;
	}	

#if defined(MBEDTLS_DEBUG_C)
	if(obj->log_fp != NULL)
    {
		fclose(obj->log_fp);
		obj->log_fp = NULL;
	}
#endif	
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
    char* cert_file = NULL;
	if (!PyArg_ParseTuple(args, "si|s",&server_name, &socket_fd, &cert_file))
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

	obj->ctx = NULL;
	obj->ctr_drbg = NULL;
	obj->conf = NULL;
	obj->entropy = NULL;
#if defined(MBEDTLS_DEBUG_C)
	obj->log_fp = fopen("C:\\mbedtls.log", "w");
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
	
    if( (obj->ctx = (mbedtls_ssl_context*)malloc(sizeof(mbedtls_ssl_context))) == NULL)
    {
		return PyErr_NoMemory();
    }


    if( (obj->ctr_drbg = (mbedtls_ctr_drbg_context*)malloc(sizeof(mbedtls_ctr_drbg_context))) == NULL)
    {
		return PyErr_NoMemory();
    }

    if( (obj->conf = (mbedtls_ssl_config*)malloc(sizeof(mbedtls_ssl_config))) == NULL)
    {
		return PyErr_NoMemory();
    }


    if( (obj->entropy = (mbedtls_entropy_context*)malloc(sizeof(mbedtls_entropy_context))) == NULL)
    {
		return PyErr_NoMemory();
    }


    mbedtls_ssl_init(obj->ctx);
    mbedtls_ctr_drbg_init(obj->ctr_drbg);
    mbedtls_ssl_config_init(obj->conf);
    mbedtls_entropy_init(obj->entropy);
#if defined(MBEDTLS_DEBUG_C)
	if(obj->log_fp != NULL)
    {
		mbedtls_ssl_conf_dbg(obj->conf, tls_debug, obj->log_fp);
	}	
#endif

    obj->error_code = mbedtls_ctr_drbg_seed(obj->ctr_drbg, mbedtls_entropy_func, obj->entropy, NULL, 0);
    if(obj->error_code != 0)
    {
		return PyErr_Format(PyExc_SystemError, "mbedtls_ctr_drbg_seed() %d", obj->error_code);
    }
	
	obj->error_code = mbedtls_ssl_config_defaults(obj->conf,
										MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);

    if(obj->error_code != 0)
    {
		return PyErr_Format(PyExc_SystemError, "mbedtls_ssl_config_defaults() %d", obj->error_code);
    }
 

    //mbedtls_ssl_conf_authmode(obj->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_authmode(obj->conf, MBEDTLS_SSL_VERIFY_NONE);
    // mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(obj->conf, mbedtls_ctr_drbg_random, obj->ctr_drbg);

    obj->error_code = mbedtls_ssl_setup(obj->ctx, obj->conf);
    if(obj->error_code != 0)
    {
		return PyErr_Format(PyExc_SystemError, "mbedtls_ssl_setup() %d", obj->error_code);
    }


	obj->error_code = mbedtls_ssl_set_hostname(obj->ctx, server_name);
    if(obj->error_code != 0)
    {
		return PyErr_Format(PyExc_SystemError, "mbedtls_ssl_set_hostname() %d", obj->error_code);
    }

	//mbedtls_ssl_set_bio(obj->ctx, &socket_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	obj->socket_fd = socket_fd;
	mbedtls_ssl_set_bio(obj->ctx, &(obj->socket_fd), tls_send, tls_recv, NULL);
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
	Py_InitModule("tls", (PyMethodDef*)tls_methods);
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






