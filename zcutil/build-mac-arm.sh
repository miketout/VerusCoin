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
  Build Verus for arm64 macOS (aarch64-apple-darwin) by invoking
  ./zcutil/build.sh with HOST set. MAKEARGS are applied to both
  dependencies and Verus itself.

  Pass extra flags to ./configure using the CONFIGURE_FLAGS environment
  variable. For example, to enable coverage instrumentation (thus enabling
  "make cov" to work), call:

      CONFIGURE_FLAGS="--enable-lcov --disable-hardening" ./zcutil/build-mac-arm.sh

  To build with debugging information, call:

      DEBUG=1 CONFIGURE_FLAGS="--enable-debug" ./zcutil/build-mac-arm.sh

  For verbose output, use:
      ./zcutil/build-mac-arm.sh V=1

  Use -mcpu=apple-m2, -mcpu=apple-m3 or -mcpu=apple-m4 in CXXFLAGS/CFLAGS for
  M2, M3 or M4 optimizations.
EOF
    exit 0
fi

set -x

HOST=aarch64-apple-darwin

export HOST
export MACOSX_DEPLOYMENT_TARGET=13.0
export CXXFLAGS="-DSSE2NEON_SUPPRESS_WARNINGS -mcpu=apple-m1 -O2 \
-fwrapv -fno-strict-aliasing -Wno-deprecated-declarations \
-Wno-deprecated-builtins -Wno-enum-constexpr-conversion \
-Wno-unknown-warning-option -Werror -Wno-error=attributes"
export CFLAGS="-DSSE2NEON_SUPPRESS_WARNINGS -mcpu=apple-m1 -O2"
export CONFIGURE_FLAGS="--enable-tests --disable-bench --with-gui=no --disable-hardening ${CONFIGURE_FLAGS-}"

exec ./zcutil/build.sh "$@" STATIC=1
