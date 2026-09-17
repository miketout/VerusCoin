OSX_MIN_VERSION=13.0
OSX_SDK_VERSION=14.0
XCODE_VERSION=15.0
XCODE_BUILD_ID=15A240d
LLD_VERSION=711

OSX_SDK=$(SDK_PATH)/Xcode-$(XCODE_VERSION)-$(XCODE_BUILD_ID)-extracted-SDK-with-libcxx-headers

darwin_AR=$(shell command -v llvm-ar || command -v ar)
darwin_NM=$(shell command -v llvm-nm || command -v nm)
darwin_OBJCOPY=$(shell command -v llvm-objcopy)
darwin_RANLIB=$(shell command -v llvm-ranlib || command -v ranlib)
darwin_STRIP=$(shell command -v llvm-strip || command -v strip)

# Flag explanations:
#
#     -mlinker-version
#
#         Ensures that modern linker features are enabled. See here for more
#         details: https://github.com/bitcoin/bitcoin/pull/19407.
#
#     -isysroot$(OSX_SDK) -nostdlibinc
#
#         Disable default include paths built into the compiler as well as
#         those normally included for libc and libc++. The only path that
#         remains implicitly is the clang resource dir.
#
#     -iwithsysroot / -iframeworkwithsysroot
#
#         Adds the desired paths from the SDK
#
#     -platform_version
#
#         Indicate to the linker the platform, the oldest supported version,
#         and the SDK used.
#
#     -no_adhoc_codesign
#
#         Disable adhoc codesigning (for now) when using LLVM tooling, to avoid
#         non-determinism issues with the Identifier field.
#
darwin_CC=clang -target $(host) -mmacos-version-min=$(OSX_MIN_VERSION) -isysroot$(OSX_SDK) -nostdlibinc -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks
darwin_CXX=clang++ -target $(host) -mmacos-version-min=$(OSX_MIN_VERSION) -isysroot$(OSX_SDK) -nostdlibinc -iwithsysroot/usr/include/c++/v1 -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)
darwin_LDFLAGS=-Wl,-platform_version,macos,$(OSX_MIN_VERSION),$(OSX_SDK_VERSION)

ifneq ($(build_os),darwin)
darwin_CFLAGS += -mlinker-version=$(LLD_VERSION)
darwin_LDFLAGS += -Wl,-no_adhoc_codesign -fuse-ld=lld
endif

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1 -g
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_cmake_system=Darwin
