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
   # Detect macOS vs Linux for sed syntax
   if [[ "$(uname -s)" == "Darwin" ]]; then
      grep -rl "MIN" ./ | xargs sed -i '' 's/MIN/RLC_MIN/g'
      grep -rl "MAX" ./ | xargs sed -i '' 's/MAX/RLC_MAX/g'
      grep -rl "ALIGN" ./ | xargs sed -i '' 's/ALIGN/RLC_ALIGN/g'
      grep -rl "rsa_t" ./ | xargs sed -i '' 's/rsa_t/rlc_rsa_t/g'
      grep -rl "rsa_st" ./ | xargs sed -i '' 's/rsa_st/rlc_rsa_st/g'
      sed -i '' -e '/^#define ep2_mul /d' include/relic_label.h
      # Fix CMake version compatibility
      sed -i '' 's/cmake_minimum_required(VERSION 3.1)/cmake_minimum_required(VERSION 3.5)/' CMakeLists.txt
      # Fix blake2 alignment issues on arm64 - remove RLC_ALIGNME for blake2 structs
      sed -i '' 's/RLC_ALIGNME( 64 ) typedef struct __blake2s_state/typedef struct __blake2s_state/' src/md/blake2.h
      sed -i '' 's/RLC_ALIGNME( 64 ) typedef struct __blake2b_state/typedef struct __blake2b_state/' src/md/blake2.h
   else
      grep -rl "MIN" ./ | xargs sed --in-place 's/MIN/RLC_MIN/g'
      grep -rl "MAX" ./ | xargs sed --in-place 's/MAX/RLC_MAX/g'
      grep -rl "ALIGN" ./ | xargs sed --in-place 's/ALIGN/RLC_ALIGN/g'
      grep -rl "rsa_t" ./ | xargs sed --in-place 's/rsa_t/rlc_rsa_t/g'
      grep -rl "rsa_st" ./ | xargs sed --in-place 's/rsa_st/rlc_rsa_st/g'
      sed --in-place -e '/^#define ep2_mul /d' include/relic_label.h
      # Fix CMake version compatibility
      sed --in-place 's/cmake_minimum_required(VERSION 3.1)/cmake_minimum_required(VERSION 3.5)/' CMakeLists.txt
      # Fix blake2 alignment issues on arm64 - remove RLC_ALIGNME for blake2 structs
      sed --in-place 's/RLC_ALIGNME( 64 ) typedef struct __blake2s_state/typedef struct __blake2s_state/' src/md/blake2.h
      sed --in-place 's/RLC_ALIGNME( 64 ) typedef struct __blake2b_state/typedef struct __blake2b_state/' src/md/blake2.h
   fi

   cd ..
   tar -czf ${RELIC}.${FORMAT} ${RELIC}
   rm ${RELIC}.test.${FORMAT}
   rm -r ${RELIC}
else
   echo "[!] ${RELIC}.tar.gz already exists." 
fi
