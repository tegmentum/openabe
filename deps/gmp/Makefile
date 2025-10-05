.PHONY: all clean distclean

include ../../Makefile.common

VERSION := 6.3.0

all: package gmp-$(VERSION)/.built

package:
	./download_gmp.sh gmp-$(VERSION)

gmp-$(VERSION)/.built: gmp-$(VERSION)
	cd $<; \
	./configure --prefix=$(DEPS_INSTALL_ZROOT) \
		--host=$(ARCH_FLAG)-apple-darwin \
		--build=$(shell uname -m)-apple-darwin \
		--enable-cxx \
		--enable-static \
		--disable-shared \
		CC="$(CC) -arch $(ARCH_FLAG)" CXX="$(CXX) -arch $(ARCH_FLAG)" \
		CFLAGS="$(CCFLAGS)" CXXFLAGS="$(CXXFLAGS)" && \
	make && \
	make install && \
	touch .built

gmp-$(VERSION): gmp-$(VERSION).tar.xz
	tar xf $^

clean:
	rm -rf gmp-$(VERSION)

distclean: clean
	rm -rf gmp-$(VERSION)*
