OSX_MIN_VERSION=13.0
OSX_SDK_VERSION=14.0
XCODE_VERSION=15.0
XCODE_BUILD_ID=15A240d
LLD_VERSION=711

OSX_SDK=$(SDK_PATH)/Xcode-$(XCODE_VERSION)-$(XCODE_BUILD_ID)-extracted-SDK-with-libcxx-headers

darwin_AR=$(shell command -v llvm-ar || command -v ar)
darwin_NM=$(shell command -v llvm-nm || command -v nm)
darwin_RANLIB=$(shell command -v llvm-ranlib || command -v ranlib)
darwin_STRIP=$(shell command -v llvm-strip || command -v strip)

# Flag explanations:
#
#     -mlinker-version
#
#         Ensures that modern linker features are enabled. See here for more
#         details: https://github.com/bitcoin/bitcoin/pull/19407.
#
#     -B$(build_prefix)/bin
#
#         Explicitly point to our binaries (e.g. cctools) so that they are
#         ensured to be found and preferred over other possibilities.
#
#     -nostdinc++ -isystem $(OSX_SDK)/usr/include/c++/v1
#
#         Forces clang to use the libc++ headers from our SDK and completely
#         forget about the libc++ headers from the standard directories
#
#         TODO: Once we start requiring a clang version that has the
#         -stdlib++-isystem<directory> flag first introduced here:
#         https://reviews.llvm.org/D64089, we should use that instead. Read the
#         differential summary there for more details.
#
darwin_CC=clang -target $(host) -mmacos-version-min=$(OSX_MIN_VERSION) --sysroot $(OSX_SDK) -mlinker-version=$(LLD_VERSION) -B$(build_prefix)/bin
darwin_CXX=clang++ -target $(host) -mmacos-version-min=$(OSX_MIN_VERSION) --sysroot $(OSX_SDK) -stdlib=libc++ -mlinker-version=$(LLD_VERSION) -B$(build_prefix)/bin -nostdinc++ -isystem $(OSX_SDK)/usr/include/c++/v1

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1 -g
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_cmake_system=Darwin
