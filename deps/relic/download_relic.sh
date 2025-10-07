#!/bin/bash

VERSION=0.7.0
FORMAT=tar.gz
LINK=https://github.com/relic-toolkit/relic
RELIC=${1:-relic-toolkit-${VERSION}}
# Use official 0.7.0 release tag
COMMIT=0.7.0

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

   echo "Apply RELIC 0.7.0 patches..."
   # Detect macOS vs Linux for sed syntax
   if [[ "$(uname -s)" == "Darwin" ]]; then
      # Fix CMake version compatibility
      sed -i '' 's/cmake_minimum_required(VERSION 3.1)/cmake_minimum_required(VERSION 3.5)/' CMakeLists.txt
      # Fix blake2 alignment issues on arm64 - remove ALIGNME for blake2 structs
      # Note: RELIC 0.7.0 uses ALIGNME instead of RLC_ALIGNME in blake2.h
      sed -i '' 's/ALIGNME( 64 ) typedef struct __blake2s_state/typedef struct __blake2s_state/' src/md/blake2.h
      sed -i '' 's/ALIGNME( 64 ) typedef struct __blake2b_state/typedef struct __blake2b_state/' src/md/blake2.h
      # Fix rand_call signature mismatch (int -> size_t) for OpenABE callback compatibility
      sed -i '' 's/void (\*rand_call)(uint8_t \*, int, void \*);/void (*rand_call)(uint8_t *, size_t, void *);/' include/relic_core.h
   else
      # Fix CMake version compatibility
      sed --in-place 's/cmake_minimum_required(VERSION 3.1)/cmake_minimum_required(VERSION 3.5)/' CMakeLists.txt
      # Fix blake2 alignment issues on arm64 - remove ALIGNME for blake2 structs
      # Note: RELIC 0.7.0 uses ALIGNME instead of RLC_ALIGNME in blake2.h
      sed --in-place 's/ALIGNME( 64 ) typedef struct __blake2s_state/typedef struct __blake2s_state/' src/md/blake2.h
      sed --in-place 's/ALIGNME( 64 ) typedef struct __blake2b_state/typedef struct __blake2b_state/' src/md/blake2.h
      # Fix rand_call signature mismatch (int -> size_t) for OpenABE callback compatibility
      sed --in-place 's/void (\*rand_call)(uint8_t \*, int, void \*);/void (*rand_call)(uint8_t *, size_t, void *);/' include/relic_core.h
   fi

   cd ..
   tar -czf ${RELIC}.${FORMAT} ${RELIC}
   rm ${RELIC}.test.${FORMAT}
   rm -r ${RELIC}
else
   echo "[!] ${RELIC}.tar.gz already exists." 
fi
