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
  Cross-build Verus for Windows (x86_64-w64-mingw32) by invoking
  ./zcutil/build.sh with HOST set. MAKEARGS are applied to both
  dependencies and Verus itself.

  Pass extra flags to ./configure using the CONFIGURE_FLAGS environment
  variable, for example:

      CONFIGURE_FLAGS="--enable-debug" ./zcutil/build-win.sh

  For verbose output, use:
      ./zcutil/build-win.sh V=1
EOF
    exit 0
fi

set -x

export HOST=x86_64-w64-mingw32

exec ./zcutil/build.sh "$@"
