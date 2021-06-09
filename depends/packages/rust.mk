package=rust
$(package)_version=1.52.1
$(package)_download_path=https://static.rust-lang.org/dist

$(package)_file_name_linux=rust-$($(package)_version)-x86_64-unknown-linux-gnu.tar.gz
$(package)_sha256_hash_linux=e024698320d76b74daf0e6e71be3681a1e7923122e3ebd03673fcac3ecc23810
$(package)_file_name_darwin=rust-$($(package)_version)-x86_64-apple-darwin.tar.gz
$(package)_sha256_hash_darwin=f0dfba507192f9b5c330b5984ba71d57d434475f3d62bd44a39201e36fa76304
$(package)_file_name_mingw32=rust-$($(package)_version)-x86_64-pc-windows-gnu.tar.gz
$(package)_sha256_hash_mingw32=358e1435347c67dbf33aa9cad6fe501a833d6633ed5d5aa1863d5dffa0349be9

# https://github.com/bazelbuild/rules_rust/blob/main/rust/known_shas.bzl
$(package)_file_name_arm_darwin=rust-$($(package)_version)-aarch64-apple-darwin.tar.gz
$(package)_sha256_hash_arm_darwin=217e9723f828c5359467d69b363a342d702bdcbbcc4107be907e6bc4531f4912

ifeq ($(build_os),darwin)
ifeq ($(build_arch),arm)
$(info $(shell tput setaf 11)[ Decker ]$(shell tput sgr0) Trying to get rust for arm-apple-darwin)
$(package)_file_name_darwin=$($(package)_file_name_arm_darwin)
$(package)_sha256_hash_darwin=$($(package)_sha256_hash_arm_darwin)
#$(info $(shell tput setaf 11)[ Decker ]$(shell tput sgr0) $($(package)_file_name_$(build_os)))
#build_darwin_DOWNLOAD = curl -v --connect-timeout $(DOWNLOAD_CONNECT_TIMEOUT) --retry $(DOWNLOAD_RETRIES) -L -f -o
else
$(package)_file_name=$($(package)_file_name_darwin)
$(package)_sha256_hash=$($(package)_sha256_hash_darwin)
endif
else ifeq ($(host_os),mingw32)
$(package)_file_name=$($(package)_file_name_mingw32)
$(package)_sha256_hash=$($(package)_sha256_hash_mingw32)
else
$(package)_file_name=$($(package)_file_name_linux)
$(package)_sha256_hash=$($(package)_sha256_hash_linux)
endif

ifeq ($(host_os),mingw32)
$(package)_build_subdir=buildos
$(package)_extra_sources = $($(package)_file_name_$(build_os))

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_file_name_$(build_os)),$($(package)_file_name_$(build_os)),$($(package)_sha256_hash_$(build_os)))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_sha256_hash_$(build_os))  $($(package)_source_dir)/$($(package)_file_name_$(build_os))" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir mingw32 && \
  tar --strip-components=1 -xf $($(package)_source) -C mingw32 && \
  mkdir buildos && \
  tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_file_name_$(build_os)) -C buildos
endef

define $(package)_stage_cmds
  ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(host_prefix)/native --disable-ldconfig --without=rust-docs && \
  cp -r ../mingw32/rust-std-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu $($(package)_staging_dir)$(host_prefix)/native/lib/rustlib
endef
else

define $(package)_stage_cmds
  ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(host_prefix)/native --disable-ldconfig --without=rust-docs
endef
endif
