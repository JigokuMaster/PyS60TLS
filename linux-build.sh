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

BUILD_TYPE=`echo $1`

if [ $BUILD_TYPE != "py22" -a $BUILD_TYPE != "py25" ]; then
  echo "Usage: ./$0 [py22 or py25]"
  exit 1
fi

$BUILD_TYPE
make linux_ext

