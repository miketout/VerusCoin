package=libarchive
$(package)_version=3.8.9
$(package)_download_path=https://github.com/libarchive/libarchive/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_file=$(package)-$($(package)_version).tar.gz
$(package)_config_opts=--with-sysroot=$(host_prefix)/lib
$(package)_config_opts+=--disable-shared --enable-static
$(package)_config_opts+=--disable-bsdtar --disable-bsdcat --disable-bsdcpio --disable-bsdunzip
$(package)_config_opts+=--without-bz2lib --without-lzma --without-zstd --without-lz4
$(package)_config_opts+=--without-libb2 --without-iconv --without-openssl --without-cng
$(package)_config_opts+=--without-xml2 --without-expat
$(package)_config_opts+=--disable-acl --disable-xattr
$(package)_config_opts_mingw32=--with-openssl
$(package)_sha256_hash=f5a6539059cf5e597dbeda37bfa4874b1e8dea063c8d93bf85a2b44af90a5bd4
$(package)_cflags+=-fPIC

$(package)_dependencies=zlib openssl
$(package)_config_env_mingw32=LIBS="-lws2_32 -lgdi32 -lcrypt32"

define $(package)_set_vars
ifeq ($(host_os),darwin)
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="$(OSX_MIN_VERSION)"
endif
ifeq ($(build_os),linux)
  $(package)_config_env=LD_LIBRARY_PATH="$(host_prefix)/lib"
endif
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  echo 'Staging dir: $($(package)_staging_dir)$(host_prefix)/' && \
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
