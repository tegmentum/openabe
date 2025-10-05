#!/bin/bash

CMD=$1
FORMAT=tar.gz
# Use OpenSSL 1.1.1 release tag (has HKDF KDF support)
# Updated for arm64 support
COMMIT=OpenSSL_1_1_1

# openssl with BP support
if [[ $CMD == "with-bp" ]]; then
   LINK=https://github.com/zeutro/openssl
   VERSION=1.1.1-dev-bp
   echo "Clone github repo @ ${LINK}"
   git clone -b patch ${LINK} openssl-${VERSION}.git
   cd openssl-${VERSION}.git
else
   LINK=https://github.com/openssl/openssl
   VERSION=1.1.1-dev
   echo "Clone github repo @ ${LINK}"
   git clone ${LINK} openssl-${VERSION}.git
   cd openssl-${VERSION}.git
   git reset --hard ${COMMIT}
fi

OPENSSL=openssl-${VERSION}
if [[ ! -f ./${OPENSSL}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   git archive --output ../openssl-${VERSION}.test.${FORMAT} HEAD 

   echo "Create final tarball: openssl-${VERSION}.${FORMAT}"
   cd ..
   mkdir -p openssl-${VERSION}
   cd openssl-${VERSION}
   tar -xf ../openssl-${VERSION}.test.${FORMAT}

   cd ..
   tar -czf openssl-${VERSION}.${FORMAT} openssl-${VERSION}
   rm openssl-${VERSION}.test.${FORMAT}
   rm -r openssl-${VERSION}
else
   echo "[!] ${OPENSSL}.${FORMAT} already exists." 
fi

