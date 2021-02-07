package=libcurl
$(package)_version=7.67.0
#$(package)_version=7.75.0
$(package)_dependencies=openssl
$(package)_download_path=https://curl.haxx.se/download
$(package)_file_name=curl-$($(package)_version).tar.gz
$(package)_sha256_hash=52af3361cf806330b88b4fe6f483b6844209d47ae196ac46da4de59bb361ab02
#$(package)_sha256_hash=4d51346fe621624c3e4b9f86a8fd6f122a143820e17889f59c18f245d2d8e7a6
$(package)_config_opts_linux=--disable-shared --enable-static --prefix=$(host_prefix) --host=x86_64-unknown-linux-gnu
$(package)_config_opts_mingw32=--enable-mingw --disable-shared --enable-static --prefix=$(host_prefix) --host=x86_64-w64-mingw32
$(package)_config_opts_darwin=--disable-shared --enable-static --prefix=$(host_prefix)
$(package)_cflags_darwin=-mmacosx-version-min=10.9
$(package)_conf_tool=./configure

ifeq ($(build_os),darwin)
define $(package)_set_vars
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="10.9"
endef
endif

ifeq ($(build_os),linux)
ifneq ($(host_os),darwin)
# linux build
define $(package)_set_vars
  $(package)_config_env=LD_LIBRARY_PATH="$(host_prefix)/lib" PKG_CONFIG_LIBDIR="$(host_prefix)/lib/pkgconfig" CPPFLAGS="-I$(host_prefix)/include" LDFLAGS="-L$(host_prefix)/lib"
endef
else
# cross-compile for darwin
define $(package)_set_vars
  $(package)_config_env+=LD_LIBRARY_PATH="$(host_prefix)/lib" PKG_CONFIG_LIBDIR="$(host_prefix)/lib/pkgconfig"
  $(package)_config_env+=CPPFLAGS="-I$(host_prefix)/include -fPIC" LDFLAGS="-L$(host_prefix)/lib -Wl,-undefined -Wl,dynamic_lookup" # https://github.com/ddnet/ddnet/commit/e8bd8459a6f556594f48f33f4d145033bc89d46f
  $(package)_config_env+=CC="$(build_prefix)/bin/$($(package)_cc)" CXX="$(build_prefix)/bin/$($(package)_cxx)"
  $(package)_config_env+=AR="$(build_prefix)/bin/$($(package)_ar)" RANLIB="$(build_prefix)/bin/$($(package)_ranlib)"
  $(package)_config_opts+=--host=$(canonical_host) --without-libpsl --disable-ldap --disable-tls-srp
endef
endif
endif

ifeq ($(build_os)$(host_os),linuxdarwin) # cross-compile for MacOS from Linux
define $(package)_config_cmds
  echo '=== config for $(package):' && \
  echo '$($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts)' && \
  echo '=== ' && \
  $($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts); \
  sed -i.old "/.*HAVE_RAND_EGD.*/d" ./lib/curl_config.h; \
  sed -i.old "/.*HAVE_BUILTIN_AVAILABLE.*/d" ./lib/curl_config.h
endef
else
define $(package)_config_cmds
  echo '=== config for $(package):' && \
  echo '$($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts)' && \
  echo '=== '
endef
endif

ifeq ($(build_os),darwin)
define $(package)_build_cmds
  $(MAKE) CPPFLAGS="-I$(host_prefix)/include -fPIC" CFLAGS='-mmacosx-version-min=10.9'
endef
else
define $(package)_build_cmds
  $(MAKE)
endef
endif

define $(package)_stage_cmds
  echo 'Staging dir: $($(package)_staging_dir)$(host_prefix)/' && \
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
