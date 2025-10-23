include ../Makefile.common

.PHONY: all clean distclean

# Determine backend-specific root directory based on ZML_LIB
ifeq ($(ZML_LIB), with_mcl)
  BACKEND_ROOT = root-mcl
  BACKEND_NAME = MCL
else ifeq ($(ZML_LIB), with_openssl)
  BACKEND_ROOT = root-openssl
  BACKEND_NAME = OpenSSL
else
  BACKEND_ROOT = root-relic
  BACKEND_NAME = RELIC
endif

DIRS=$(DEPS_PACKAGES)
# Absolute path to backend-specific root directory
BACKEND_PREFIX := $(shell pwd)/$(BACKEND_ROOT)

all: $(DIRS)
	@echo "Building dependencies for $(BACKEND_NAME) backend into $(BACKEND_ROOT)/"
	mkdir -p $(BACKEND_ROOT)/lib
	mkdir -p $(BACKEND_ROOT)/bin
ifndef NO_DEPS
	for d in $(DIRS); do \
		make -C $$d PREFIX=$(BACKEND_PREFIX); \
	done
endif
	@echo "Creating/updating symlink: root -> $(BACKEND_ROOT)"
	@rm -rf root
	@ln -sf $(BACKEND_ROOT) root
	@echo "Dependencies installed to $(BACKEND_ROOT)/"
	@echo "Active backend: $(BACKEND_NAME) (via root/ symlink)"

clean: $(DIRS)
	@echo "Cleaning $(BACKEND_NAME) backend ($(BACKEND_ROOT))"
	rm -rf $(BACKEND_ROOT)
	for d in gmp relic openssl gtest mcl; do \
		make -C $$d clean 2>/dev/null || true; \
	done

clean-all:
	@echo "Cleaning ALL backends"
	rm -rf root root-mcl root-relic root-openssl
	for d in gmp relic openssl gtest mcl; do \
		make -C $$d clean 2>/dev/null || true; \
	done

distclean: clean-all
	for d in gmp relic openssl gtest mcl; do \
		make -C $$d distclean 2>/dev/null || true; \
	done
