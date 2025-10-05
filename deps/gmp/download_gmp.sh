#!/bin/bash

VERSION=6.3.0
FORMAT=tar.xz
LINK=https://gmplib.org/download/gmp
GMP=${1:-gmp-${VERSION}}

if [[ ! -f ${GMP}.${FORMAT} ]]; then
   echo "Downloading GMP ${VERSION} from ${LINK}..."
   curl -L -o ${GMP}.${FORMAT} ${LINK}/gmp-${VERSION}.${FORMAT}
else
   echo "[!] ${GMP}.${FORMAT} already exists."
fi
