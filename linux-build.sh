#!/bin/bash 

set -e

if [ $# != 1 ]; then
  echo "Usage: no args."
  exit 1
fi

py22()
{
    export PYTHON_PATH=`realpath ~/Dev/C/Python-2.2.2`
    export PYTHON_LIB="-lpython2.2"
}

py25()
{
    export PYTHON_PATH=`realpath ~/Dev/C/Python-2.5`
    export PYTHON_LIB="-lpython2.5"
}

BUILD_TARGET=`echo $1`

if [ $BUILD_TARGET != "py22" -a $BUILD_TARGET != "py25" ]; then
  echo "Usage: ./$0 [py22 or py25]"
  exit 1
fi

$BUILD_TARGET
make -B linux_ext

