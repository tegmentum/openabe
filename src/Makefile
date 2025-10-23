include Makefile.inc
include ../Makefile.common

.PHONY: all clean header objdir

CC ?= gcc

# Object file directory for native builds
OBJDIR := .
# Note: Using src/ directory for object files for now to maintain compatibility
# TODO: Move to ../build-native after testing

OABE_INCLUDE_DIR := $(INCLUDE_ROOT)/openabe
CXX11FLAGS += $(CXXFLAGS)

# RELIC support removed - MCL is the only backend

GTESTLIBS  = -lgtest -lpthread

OABE_SHLIB = libopenabe.$(SHLIB)
OABE_KEYS = keys/zkdf.o keys/zkey.o keys/zpkey.o keys/zkeystore.o keys/zsymkey.o
OABE_LOW = ske/zcontextske.o pke/zcontextpke.o pksig/zcontextpksig.o \
          abe/zcontextabe.o abe/zcontextcca.o abe/zcontextcpwaters.o abe/zcontextkpgpsw.o
OABE_TOOLS = tools/zlsss.o tools/zprng.o

# EC implementation: Always use OpenSSL for ECDSA (MCL is for pairings only)
# MCL pairing backend uses stubs for low-level EC ops (PKSIG/ECDSA works via abstraction)
OABE_EC_IMPL = zecdsa_openssl.o zelement_ec_stubs.o

# MCL is the only supported backend
OABE_ZML = zml/zgroup.o zml/zpairing.o zml/zelliptic.o zml/zelement_ec.o zml/zelement_bp.o zml/zelement_mcl.o zml/zstandard_serialization.o $(OABE_EC_IMPL)
OABE_UTILS = utils/zkeymgr.o utils/zcryptoutils.o utils/zcontainer.o utils/zbenchmark.o utils/zerror.o utils/zcontainer.o \
            utils/zciphertext.o utils/zpolicy.o utils/zattributelist.o utils/zdriver.o utils/zfunctioninput.o utils/zcurveinfo.o
            
OABE_OBJ_TARGETS = zobject.o openabe.o zcontext.o zcrypto_box.o zsymcrypto.o zparser.o zscanner.o \
                  $(OABE_ZML) $(OABE_KEYS) $(OABE_LOW) $(OABE_TOOLS) $(OABE_UTILS) openssl_init.o $(OS_OBJS)

# MCL is the only supported backend
OABE_OBJ_FILES = zobject.o openabe.o zgroup.o zlsss.o zerror.o zpairing.o zelliptic.o zelement_ec.o zelement_bp.o zelement_mcl.o $(OABE_EC_IMPL) zcontainer.o zciphertext.o \
	     zkey.o zpkey.o zkeystore.o zfunctioninput.o zcontext.o zpolicy.o zsymkey.o zprng.o zattributelist.o \
	     zcontextske.o zcontextpke.o zcontextpksig.o zcontextabe.o zcontextcpwaters.o zcontextkpgpsw.o \
	     zcontextcca.o zkdf.o zkeymgr.o zcryptoutils.o zcrypto_box.o zbenchmark.o zparser.o zscanner.o zdriver.o zsymcrypto.o \
	     openssl_init.o zstandard_serialization.o zcurveinfo.o $(OS_OBJS)
	     
ifeq ($(OS),Windows_NT)
    LDFLAGS += -L/mingw64/bin
endif

ifeq ($(ENABLE_GCOV), yes)
  CXXFLAGS += $(COVERAGE_CFLAGS)
  LDFLAGS += $(COVERAGE_LINKER)
  SHFLAGS += $(COVERAGE_LINKER)
endif

ZSYM_OBJS = zobject.o zerror.o zprng.o zsymcrypto.o

LIBRARYH=header

GENFILES = location.hh position.hh stack.hh *.tab.* zscanner.cpp

PROGRAMS = test_libopenabe test_zml test_zml1 test_zml2 test_policy test_abe test_pke test_ske test_zsym test_keystore bench_libopenabe profile_libopenabe fuzz_policy fuzz_attrlist test_standard_serialization

all: $(OABELIB) $(ZSYMLIB) $(PROGRAMS)

zml/zelement_mcl.o:
	$(CC) $(CCFLAGS) -c zml/zelement_mcl.c -o zelement_mcl.o

zecdsa_openssl.o: zml/zecdsa_openssl.cpp
	$(CXX) $(CXXFLAGS) -c zml/zecdsa_openssl.cpp -o zecdsa_openssl.o

zecdsa_mcl.o: zml/zecdsa_mcl.cpp
	$(CXX) $(CXXFLAGS) -c zml/zecdsa_mcl.cpp -o zecdsa_mcl.o

zelement_ec_stubs.o: zml/zelement_ec_stubs.cpp
	$(CXX) $(CXXFLAGS) -c zml/zelement_ec_stubs.cpp -o zelement_ec_stubs.o

zparser.o: zparser.yy
	$(BISON) -d -v zparser.yy
	cp *.hh $(OABE_INCLUDE_DIR)
	$(CXX) $(CXXFLAGS) -c -o zparser.o zparser.tab.cc

zscanner.o: zscanner.ll
	$(FLEX) --outfile=zscanner.cpp  $<
	$(CXX) $(CXXFLAGS) -c zscanner.cpp -o zscanner.o

header:
	mkdir -p $(OABE_INCLUDE_DIR)
	cp -r include/openabe/* $(OABE_INCLUDE_DIR)
	
# provides PK, ABE, AEAD and crypto tools
$(OABELIB): $(LIBRARYH) $(OABE_OBJ_TARGETS)
	$(AR) rcs $@ $(OABE_OBJ_FILES)
	$(CXX) $(SHFLAGS) -o $(OABE_SHLIB) $(OABE_OBJ_FILES) $(SHLIB_PATH) $(OABELDSHLIBS)
	mkdir -p $(OABE_LIB_ROOT)
	cp $@ $(OABE_LIB_ROOT)
	cp $(OABE_SHLIB) $(OABE_LIB_ROOT)

# provides only AEAD impl for integration with libzclient
$(ZSYMLIB): $(OABELIB)
	$(AR) rcs $(ZSYMLIB) $(ZSYM_OBJS)
	cp $@ $(OABE_LIB_ROOT)

test:
	./test_libopenabe || exit 1
	./test_zml || exit 1
	./test_abe || exit 1
	./test_pke || exit 1
	./test_ske || exit 1
	./test_keystore || exit 1

test_libopenabe: $(OABELIB)
	$(CXX) -o test_libopenabe $(CXX11FLAGS) $(LDFLAGS) -L. test_libopenabe.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_zml: $(OABELIB)
	$(CXX) -o test_zml $(CXX11FLAGS) $(LDFLAGS) -L. test_zml.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_zml1: $(OABELIB)
	$(CXX) -o test_zml1 $(CXX11FLAGS) $(LDFLAGS) -L. test_zml1.cpp $(OABELIB) $(OABELDLIBS) -lpthread

test_zml2: $(OABELIB)
	$(CXX) -o test_zml2 $(CXX11FLAGS) $(LDFLAGS) -L. test_zml2.cpp $(OABELIB) $(OABELDLIBS) -lpthread

test_policy: $(OABELIB)
	$(CXX) -o test_policy $(CXX11FLAGS) $(LDFLAGS) -L. test_policy.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_abe: $(OABELIB)
	$(CXX) -o test_abe $(CXX11FLAGS) $(LDFLAGS) -L. test_abe.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_pke: $(OABELIB)
	$(CXX) -o test_pke $(CXX11FLAGS) $(LDFLAGS) -L. test_pke.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_ske: $(OABELIB)
	$(CXX) -o test_ske $(CXX11FLAGS) $(LDFLAGS) -L. test_ske.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_keystore: $(OABELIB)
	$(CXX) -o test_keystore $(CXX11FLAGS) $(LDFLAGS) -L. test_keystore.cpp $(OABELIB) $(OABELDLIBS) $(GTESTLIBS)

test_standard_serialization: $(OABELIB)
	$(CXX) -o test_standard_serialization $(CXX11FLAGS) $(LDFLAGS) -L. test_standard_serialization.cpp $(OABELIB) $(OABELDLIBS) -lpthread

bench_libopenabe: $(OABELIB)
	$(CXX) -o bench_libopenabe $(CXX11FLAGS) $(LDFLAGS) -L. bench_libopenabe.cpp $(OABELIB) $(OABELDLIBS) $(BOOST_SYSTEM) $(BOOST_THREAD)

profile_libopenabe: $(OABELIB)
	$(CXX) -o profile_libopenabe $(CXX11FLAGS) $(LDFLAGS) -L. profile_libopenabe.cpp $(OABELIB) $(OABELDLIBS)

fuzz_policy: $(OABELIB)
	$(CXX) -o fuzz_policy $(CXX11FLAGS) $(LDFLAGS) -L. fuzz_policy.cpp $(OABELIB) $(OABELDLIBS)

fuzz_attrlist: $(OABELIB)
	$(CXX) -o fuzz_attrlist $(CXX11FLAGS) $(LDFLAGS) -L. fuzz_attrlist.cpp $(OABELIB) $(OABELDLIBS)

test_zsym: $(ZSYMLIB)
	$(CXX) -o test_zsym $(CXX11FLAGS) $(LDFLAGS) -L. test_zsym.cpp $(ZSYMLIB) $(ZSYM_DEP_LIBS)

clean:
	-rm -rf *.o *.dSYM a.out zparser.output $(PROGRAMS) $(OABELIB) $(OABE_SHLIB) $(ZSYMLIB) $(GENFILES)
	-rm -f librelic*.$(SHLIB) libcrypto.$(SHLIB) libsl.$(SHLIB) libgtest*.$(SHLIB)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

%.o: %.c
	$(CC) $(CXXFLAGS) -c $<
