package=libarchive
$(package)_version=3.7.7
$(package)_download_path=https://github.com/libarchive/libarchive/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_file=$(package)-$($(package)_version).tar.gz
$(package)_config_opts=--with-sysroot=$(host_prefix)/lib
$(package)_config_opts_linux=--disable-bsdtar --disable-bsdcpio --disable-shared --enable-static --prefix=$(host_prefix) --host=$(HOST)
$(package)_config_opts_mingw32=--disable-bsdtar --disable-bsdcpio --disable-shared --enable-static --prefix=$(host_prefix) --host=x86_64-w64-mingw32
$(package)_config_opts_darwin=--without-zstd --without-lz4 --disable-bsdtar --disable-bsdcpio --disable-shared --enable-static --prefix=$(host_prefix)
$(package)_sha256_hash=4cc540a3e9a1eebdefa1045d2e4184831100667e6d7d5b315bb1cbc951f8ddff
$(package)_cflags_darwin=-mmacosx-version-min=$(OSX_MIN_VERSION)
$(package)_conf_tool=./configure

$(package)_dependencies=zlib

ifeq ($(build_os),darwin)
define $(package)_set_vars
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="$(OSX_MIN_VERSION)"
endef
endif

ifeq ($(build_os),linux)
define $(package)_set_vars
  $(package)_config_env=LD_LIBRARY_PATH="$(host_prefix)/lib" PKG_CONFIG_LIBDIR="$(host_prefix)/lib/pkgconfig" CPPFLAGS="-I$(host_prefix)/include" LDFLAGS="-L$(host_prefix)/lib"
endef
endif


define $(package)_config_cmds
  echo '=== config for $(package):' && \
  echo '$($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts)' && \
  echo '=== ' && \
  $($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts)
endef

ifeq ($(build_os),darwin)
define $(package)_build_cmds
  $(MAKE) CPPFLAGS="-I$(host_prefix)/include -fPIC" CFLAGS="-mmacosx-version-min=$(OSX_MIN_VERSION)"
endef
else
define $(package)_build_cmds
  $(MAKE) CPPFLAGS="-I$(host_prefix)/include -fPIC"
endef
endif

define $(package)_stage_cmds
  echo 'Staging dir: $($(package)_staging_dir)$(host_prefix)/' && \
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
