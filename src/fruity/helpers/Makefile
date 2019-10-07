macos_cc := $(shell xcrun --sdk macosx -f clang)
ios_cc := $(shell xcrun --sdk iphoneos -f clang)
cflags := -Wall -pipe -Oz -g
ldflags := -Wl,-dead_strip

build: build/resolver build/resolver.dylib

test: build
	@build/resolver

build/resolver: resolver.c
	@mkdir -p $(@D)
	$(macos_cc) \
		-isysroot $(shell xcrun --sdk macosx --show-sdk-path) \
		-arch x86_64 \
		$(cflags) \
		-DBUILDING_TEST_PROGRAM \
		$< \
		-o build/resolver \
		$(ldflags)

build/resolver.dylib: resolver.c
	@mkdir -p $(@D)
	$(ios_cc) \
		-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
		-arch arm64 \
		$(cflags) \
		$< \
		-o build/resolver.dylib \
		-dynamiclib \
		-nostdlib \
		$(ldflags)

.PHONY: build test
