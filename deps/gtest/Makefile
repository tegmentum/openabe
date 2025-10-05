.PHONY: all clean

VERSION := 1.8.0

include ../../Makefile.common

all: package googletest-release-$(VERSION)/.built

DEST_LIBDIR := $(DEPS_INSTALL_ZROOT)/lib
DEST_INCLUDEDIR := $(DEPS_INSTALL_ZROOT)/include

package:
	./download_gtest.sh $(VERSION)

googletest-release-$(VERSION)/.built: googletest-release-$(VERSION)
	# Fix CMake version compatibility for macOS
	@if [[ "$(shell uname -s)" == "Darwin" ]]; then \
		sed -i '' 's/cmake_minimum_required(VERSION [0-9.]*)/cmake_minimum_required(VERSION 3.5)/' $</googletest/CMakeLists.txt; \
	else \
		sed -i 's/cmake_minimum_required(VERSION [0-9.]*)/cmake_minimum_required(VERSION 3.5)/' $</googletest/CMakeLists.txt; \
	fi
	cd $<; \
	mkdir -p build && cd build/ && \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(DEPS_INSTALL_ZROOT) -DCMAKE_POLICY_VERSION_MINIMUM=3.5 ../googletest/ && \
	make install && \
	touch ../.built

googletest-release-$(VERSION): googletest-release-$(VERSION).zip
	unzip $^

clean:
	rm -rf googletest-release-$(VERSION)

distclean:
	rm -rf googletest-release-$(VERSION)*
