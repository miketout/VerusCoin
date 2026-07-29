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

      CONFIGURE_FLAGS="--enable-lcov" ./zcutil/build-mac.sh

  To build with debugging information, call:

      DEBUG=1 CONFIGURE_FLAGS="--enable-debug" ./zcutil/build-mac.sh

  For verbose output, use:
      ./zcutil/build-mac.sh V=1
EOF
    exit 0
fi

set -x

export HOST=x86_64-apple-darwin

exec ./zcutil/build.sh "$@"
