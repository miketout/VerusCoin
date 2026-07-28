#!/bin/bash

set -eu -o pipefail

cd "$(dirname "$(readlink -f "$0")")/.."

if [ "x$*" = 'x--help' ]
then
    cat <<EOF
Usage:

$0 --help
  Show this help message and exit.

$0 [ MAKEARGS... ]
  Build Verus for x86_64 macOS by invoking ./zcutil/build.sh. MAKEARGS are
  applied to both dependencies and Verus itself.

  Pass extra flags to ./configure using the CONFIGURE_FLAGS environment
  variable. For example, to enable coverage instrumentation (thus enabling
  "make cov" to work), call:

      CONFIGURE_FLAGS="--enable-lcov --disable-hardening" ./zcutil/build-mac.sh

  To build with debugging information, call:

      DEBUG=1 CONFIGURE_FLAGS="--enable-debug" ./zcutil/build-mac.sh

  For verbose output, use:
      ./zcutil/build-mac.sh V=1
EOF
    exit 0
fi

set -x

PREFIX="$PWD/depends/$(./depends/config.guess)"

export CPPFLAGS="-I$PREFIX/include -arch x86_64"
export LDFLAGS="-L$PREFIX/lib -L/usr/local/opt/libb2/lib -arch x86_64 -Wl,-no_pie"
export CXXFLAGS="-arch x86_64 -I$PREFIX/include -fwrapv -fno-strict-aliasing \
-Wno-deprecated-declarations -Wno-deprecated-builtins -Wno-enum-constexpr-conversion \
-Wno-unknown-warning-option -Werror -Wno-error=attributes -g"
export CONFIGURE_FLAGS="--prefix=${PREFIX} --with-gui=no --disable-hardening ${CONFIGURE_FLAGS-}"

exec ./zcutil/build.sh "$@" NO_GTEST=1 STATIC=1
