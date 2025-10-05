#!/bin/bash

VERSION=0.5.0
FORMAT=tar.gz
LINK=https://github.com/relic-toolkit/relic
RELIC=${1:-relic-toolkit-${VERSION}}
# commit of as of 1/9/2019
# comment 'Update LABEL with recent changes'
COMMIT=b984e901ba78c83ea4093ea96addd13628c8c2d0

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${RELIC}.git
cd ${RELIC}.git
git reset --hard ${COMMIT}

if [[ ! -f ${RELIC}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   git archive --output ../${RELIC}.test.${FORMAT} HEAD 

   echo "Create final tarball: ${RELIC}.${FORMAT}"
   cd ..
   mkdir ${RELIC}
   cd ${RELIC}
   tar -xf ../${RELIC}.test.${FORMAT}

   echo "Fix symbols..."
   grep -rl "MIN" ./ | xargs sed -i '' 's/MIN/RLC_MIN/g'
   grep -rl "MAX" ./ | xargs sed -i '' 's/MAX/RLC_MAX/g'
   grep -rl "ALIGN" ./ | xargs sed -i '' 's/ALIGN/RLC_ALIGN/g'
   grep -rl "rsa_t" ./ | xargs sed -i '' 's/rsa_t/rlc_rsa_t/g'
   grep -rl "rsa_st" ./ | xargs sed -i '' 's/rsa_st/rlc_rsa_st/g'
   sed -i '' -e '/^#define ep2_mul /d' include/relic_label.h

   cd ..
   tar -czf ${RELIC}.${FORMAT} ${RELIC}
   rm ${RELIC}.test.${FORMAT}
   rm -r ${RELIC}
else
   echo "[!] ${RELIC}.tar.gz already exists." 
fi
