#!/bin/bash

CMD=$1
FORMAT=tar.gz
# Use OpenSSL 3.3.2 LTS release (has working EC support and HKDF)
VERSION=3.3.2
LINK=https://github.com/openssl/openssl

echo "Downloading OpenSSL ${VERSION} from ${LINK}"
git clone --depth 1 --branch openssl-${VERSION} ${LINK} openssl-${VERSION}.git
cd openssl-${VERSION}.git

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

