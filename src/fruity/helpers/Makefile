macos_cc := $(shell xcrun --sdk macosx -f clang)
ios_cc := $(shell xcrun --sdk iphoneos -f clang)
cflags := -Wall -pipe -Oz -g
ldflags := -Wl,-dead_strip

build: build/fetcher.dylib build/resolver.dylib build/test-fetcher build/test-resolver

test: build
	@build/test-fetcher
	@build/test-resolver

build/%.dylib: %.c
	@mkdir -p $(@D)
	$(ios_cc) \
		-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
		-arch arm64 \
		$(cflags) \
		$< \
		-o $@ \
		-dynamiclib \
		-nostdlib \
		$(ldflags)

build/test-%: %.c
	@mkdir -p $(@D)
	$(macos_cc) \
		-isysroot $(shell xcrun --sdk macosx --show-sdk-path) \
		-arch x86_64 \
		$(cflags) \
		-DBUILDING_TEST_PROGRAM \
		$< \
		-o $@ \
		$(ldflags)

.PHONY: build test
