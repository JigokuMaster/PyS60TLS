#!/bin/bash 

set -e

MBEDTLS_PATH=`realpath ~/Dev/C/mbedtls-3.4.1`
PYTHON_PATH=`realpath ~/Dev/C/Python-2.2.2`

g++ -w -shared -fPIC \
    -I. \
    -I$PYTHON_PATH \
    -I$PYTHON_PATH/Include \
    -I$MBEDTLS_PATH/include \
    tlsmodule.cpp \
    -L$MBEDTLS_PATH/library \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -L$PYTHON_PATH -lpython2.2 \
    -o /tmp/tls.so

$PYTHON_PATH/python tests.py
