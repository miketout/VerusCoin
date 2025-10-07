#!/bin/bash
set -eu -o pipefail

if [ "x$*" = 'x--help' ]
then
    cat <<EOF
Usage:

$0 --help
  Show this help message and exit.

$0 [ --enable-lcov ] [ --enable-debug ] [ MAKEARGS... ]
  Build Komodo and most of its transitive dependencies from
  source. MAKEARGS are applied to both dependencies and Komodo itself. 
  If --enable-lcov is passed, Komodo is configured to add coverage
  instrumentation, thus enabling "make cov" to work.
  If --enable-debug is passed, Komodo is built with debugging information. It
  must be passed after the previous arguments, if present.
EOF
    exit 0
fi

# If --enable-lcov is the first argument, enable lcov coverage support:
LCOV_ARG=''
HARDENING_ARG='--disable-hardening'
if [ "x${1:-}" = 'x--enable-lcov' ]
then
    LCOV_ARG='--enable-lcov'
    HARDENING_ARG='--disable-hardening'
    shift
fi

# If --enable-debug is the next argument, enable debugging
DEBUGGING_ARG=''
if [ "x${1:-}" = 'x--enable-debug' ]
then
    DEBUG=1
    export DEBUG
    DEBUGGING_ARG='--enable-debug'
    shift
fi

TRIPLET=`./depends/config.guess`
PREFIX="$(pwd)/depends/$TRIPLET"

make "$@" -C ./depends v=1 NO_PROTON=1 NO_QT=1 HOST=aarch64-apple-darwin
./autogen.sh

CXXFLAGS="-g0 -O2 -Wno-unknown-warning-option -Wno-deprecated-declarations -fwrapv -fno-strict-aliasing" \
CONFIG_SITE="$PWD/depends/aarch64-apple-darwin/share/config.site" ./configure --disable-tests --disable-bench --with-gui=no --host=aarch64-apple-darwin "$HARDENING_ARG" "$LCOV_ARG" "$DEBUGGING_ARG"
MACOSX_DEPLOYMENT_TARGET=10.4 make "$@" NO_GTEST=1 STATIC=1
