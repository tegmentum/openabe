include ../Makefile.common

.PHONY: all clean

DIRS=$(DEPS_PACKAGES)
# relic openssl gtest
all: $(DIRS)
	mkdir -p root/lib
	mkdir -p root/bin
ifndef NO_DEPS
	for d in $(DIRS); do \
		make -C $$d; \
	done
endif

clean: $(DIRS)
	rm -rf root
	for d in gmp relic openssl gtest mcl; do \
		make -C $$d clean 2>/dev/null || true; \
	done

distclean: clean
	rm -rf root
	for d in gmp relic openssl gtest mcl; do \
		make -C $$d distclean 2>/dev/null || true; \
	done
