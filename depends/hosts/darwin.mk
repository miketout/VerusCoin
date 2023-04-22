OSX_MIN_VERSION=10.8
LD64_VERSION=274.2
darwin_CC=gcc-8 -target $(host) -mmacosx-version-min=$(OSX_MIN_VERSION) -fvisibility=hidden -fvisibility-inlines-hidden --sysroot $(shell xcrun --show-sdk-path) -mlinker-version=$(LD64_VERSION)
darwin_CXX=g++-8 -target $(host) -mmacosx-version-min=$(OSX_MIN_VERSION) -fvisibility=hidden -fvisibility-inlines-hidden --sysroot $(shell xcrun --show-sdk-path) -mlinker-version=$(LD64_VERSION)

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)

darwin_release_CFLAGS=-O3
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O0
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_native_toolchain=native_cctools

