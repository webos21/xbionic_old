# Copyright 2013 Cheolmin Jo (webos21@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

######################################################
#                        XI                          #
#----------------------------------------------------#
# File    : build_linux32.mk                         #
# Version : 0.1.0                                    #
# Desc    : properties file for LINUX 32bit build.   #
#----------------------------------------------------#
# History)                                           #
#   - 2011/06/15 : Created by cmjo                   #
######################################################


########################
# Programs
########################
include ${basedir}/buildx/antmk/shprog.mk


########################
# Build Configuration
########################
build_cfg_target   = linux32
build_cfg_linux    = 1
build_cfg_posix    = 1
build_cfg_arch     = x86


########################
# Directories
########################
build_tool_dir     = 


########################
# Program Definition
########################
build_tool_as      = ${build_tool_dir}as
build_tool_cc      = ${build_tool_dir}gcc
build_tool_cxx     = ${build_tool_dir}g++
build_tool_linker  = ${build_tool_dir}g++
build_tool_ar      = ${build_tool_dir}ar
build_tool_ranlib  = ${build_tool_dir}ranlib


########################
# Compile Flags
########################
#build_run_a        = 1
build_run_so       = 1
build_run_test     = 1

build_opt_a_pre    = lib
build_opt_a_ext    = a
build_opt_so_pre   = lib
build_opt_so_ext   = so
build_opt_exe_ext  =

build_opt_c        = -m32 -march=i686 -g -Wall -Wextra -Wdeclaration-after-statement -O3 -DXI_BUILD_${build_cfg_target} -D_REENTRANT -D_THREAD_SAFE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
build_opt_cxx      = -m32 -march=i686 -g -Wall -Wextra -O3 -DXI_BUILD_${build_cfg_target} -D_REENTRANT -D_THREAD_SAFE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
build_opt_fPIC     = -fPIC
build_opt_ld       = -m32 -march=i686 -g -Wl,--no-undefined
build_opt_ld_so    = -shared -Wl,-soname,
build_opt_ld_rpath = -Wl,-rpath-link,
build_opt_ld_noud  = -Wl,--no-undefined
build_opt_ld_mgwcc =
build_opt_ld_mgwcx =


########################
# Compile Target : xbionic
########################
build_xbionic_opt_c      = -m32 -Wall -Wextra -isystem ${basedir}/xbionic/libc/arch-${build_cfg_arch}/include -isystem ${basedir}/xbionic/libc/include -isystem ${basedir}/xbionic/libc/kernel/common -isystem ${basedir}/xbionic/libc/kernel/arch-${build_cfg_arch}
build_xbionic_opt_cxx    = -m32 -Wall -Wextra -isystem ${basedir}/xbionic/libc/arch-${build_cfg_arch}/include -isystem ${basedir}/xbionic/libc/include -isystem ${basedir}/xbionic/libc/kernel/common -isystem ${basedir}/xbionic/libc/kernel/arch-${build_cfg_arch}
build_xbionic_opt_ld     = -m32 -nodefaultlibs -nostdlib

build_xb_libc_cflags     = -DWITH_ERRLIST -DANDROID_CHANGES -D_LIBC=1 -DINET6 -DPOSIX_MISTAKE -DLOG_ON_HEAP_ERROR -I${basedir}/xbionic/libc/private
build_xb_libc_ldflags    =


# -DWITH_ERRLIST -DANDROID_CHANGES -D_LIBC=1 -DFLOATING_POINT -DINET6 -DPOSIX_MISTAKE -DLOG_ON_HEAP_ERROR  -std=gnu99 -I${basedir}/xbionic/libc/private
# -DWITH_ERRLIST
# -DANDROID_CHANGES
# -D_LIBC=1
# -DFLOATING_POINT
# -DINET6
# -DPOSIX_MISTAKE
# -DLOG_ON_HEAP_ERROR
# -I${basedir}/xbionic/libc/private

# -DPLATFORM_SDK_VERSION=18 -DANDROID_SMP=1 -DHAVE_UNWIND_CONTEXT_STRUCT -DHAVE_DLADDR=0
# -DPLATFORM_SDK_VERSION=18
# -DANDROID_SMP=1
# -DHAVE_UNWIND_CONTEXT_STRUCT
# -DHAVE_DLADDR=0
# -D_REENTRANT
# -I${basedir}/xbionic/libc
# -I${basedir}/xbionic/libc/stdio
# -I${basedir}/xbionic/libc/string
# -I${basedir}/xbionic/libc/upstream-netbsd/libc/include
# -I${basedir}/xbionic/libc/stdlib
# -I${basedir}/xbionic/libm/include
# -I${basedir}/external/safe-iop/include

build_xb_libc_src_sspbin = libbionic_ssp.a
build_xb_libc_src_ssp_cf = ${build_xb_libc_cflags} -fno-stack-protector
build_xb_libc_src_ssp_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_ssp_in = libc/bionic/__stack_chk_fail.cpp
build_xb_libc_src_ssp_ex = 
build_xb_libc_src_ssp_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_ssp_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_ufbbin = libc_freebsd.a
build_xb_libc_src_ufb_cf = ${build_xb_libc_cflags} -I${basedir}/xbionic/libc/upstream-freebsd -include ${basedir}/xbionic/libc/upstream-freebsd/freebsd-compat.h
build_xb_libc_src_ufb_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_ufb_in = libc/upstream-freebsd/**/*.c
build_xb_libc_src_ufb_ex = 
build_xb_libc_src_ufb_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_ufb_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_unbbin = libc_netbsd.a
build_xb_libc_src_unb_cf = ${build_xb_libc_cflags} -I${basedir}/xbionic/libc/stdio -I${basedir}/xbionic/libm/include -I${basedir}/xbionic/libc/upstream-netbsd -I${basedir}/xbionic/libc/upstream-netbsd/libc/include -include ${basedir}/xbionic/libc/upstream-netbsd/netbsd-compat.h
build_xb_libc_src_unb_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_unb_in = libc/upstream-netbsd/**/*.c
build_xb_libc_src_unb_ex = libc/upstream-netbsd/libc/regex/engine.c
build_xb_libc_src_unb_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_unb_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_bi2bin = libc_bionic.a
build_xb_libc_src_bi2_cf = ${build_xb_libc_cflags} -I${basedir}/xbionic/libc -I${basedir}/xbionic/libc/stdlib -I${basedir}/external/safe-iop/include -I${basedir}/external/android/system/core/include
build_xb_libc_src_bi2_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_bi2_in = libc/bionic/*.cpp
build_xb_libc_src_bi2_ex = libc/bionic/__stack_chk_fail.cpp, libc/bionic/debug_*.cpp, libc/bionic/malloc_debug_*.cpp, libc/bionic/libc_init_static.cpp, libc/bionic/pthread_create.cpp, libc/bionic/pthread_key.cpp
build_xb_libc_src_bi2_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_bi2_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)


build_xb_libc_src_combin = libc_common.a

#####################################
# libc_common : total 
build_xb_libc_src_com_cf = ${build_xb_libc_cflags}
build_xb_libc_src_com_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_com_in = libc/arch-${build_cfg_arch}/syscalls/*.S, libc/unistd/*.c, libc/stdio/*.c, libc/stdlib/*.c, libc/string/*.c, libc/wchar/*.c, libc/inet/*.c, libc/tzcode/*.c, libc/bionic/*.c, libc/netbsd/**/*.c
build_xb_libc_src_com_ex = libc/netbsd/net/*_r.c, libc/netbsd/resolv/res_random.c
build_xb_libc_src_com_mk = $(wildcard $(basedir)/xbionic/libc/arch-${build_cfg_arch}/syscalls/*.S)
build_xb_libc_src_com_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)
#####################################

build_xb_libc_src_crt_cf = ${build_xb_libc_cflags} -std=gnu99 -DUSE_SSE2=1 -DUSE_SSE3=1 -DPLATFORM_SDK_VERSION=18
build_xb_libc_src_crt_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_crt_in = libc/bionic/crtbrand.c, libc/arch-${build_cfg_arch}/bionic/crt*.S, libc/arch-${build_cfg_arch}/bionic/crt*.c
build_xb_libc_src_crt_ex =
build_xb_libc_src_crt_mk = $(wildcard $(basedir)/xbionic/libc/arch-${build_cfg_arch}/syscalls/*.S)
build_xb_libc_src_crt_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_sys_cf = ${build_xb_libc_cflags} -std=gnu99
build_xb_libc_src_sys_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_syc_in = libc/arch-${build_cfg_arch}/**/*.S, libc/arch-${build_cfg_arch}/**/*.c
build_xb_libc_src_syc_ex = libc/arch-${build_cfg_arch}/bionic/crt*.S, libc/arch-${build_cfg_arch}/bionic/crt*.c
build_xb_libc_src_sys_mk = $(wildcard $(basedir)/xbionic/libc/arch-${build_cfg_arch}/syscalls/*.S)
build_xb_libc_src_sys_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_uni_cf = ${build_xb_libc_cflags} -std=gnu99 -I${basedir}/xbionic/libc/stdlib
build_xb_libc_src_uni_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_uni_in = libc/unistd/*.c
build_xb_libc_src_uni_ex =
build_xb_libc_src_uni_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_uni_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_sio_cf = ${build_xb_libc_cflags} -std=gnu99
build_xb_libc_src_sio_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_sio_in = libc/stdio/*.c
build_xb_libc_src_sio_ex =
build_xb_libc_src_sio_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_sio_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_slb_cf = ${build_xb_libc_cflags} -std=gnu99 -I${basedir}/xbionic/libm/include
build_xb_libc_src_slb_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_slb_in = libc/stdlib/*.c
build_xb_libc_src_slb_ex =
build_xb_libc_src_slb_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_slb_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_str_cf = ${build_xb_libc_cflags} -std=gnu99
build_xb_libc_src_str_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_str_in = libc/string/*.c
build_xb_libc_src_str_ex =
build_xb_libc_src_str_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_str_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_wch_cf = ${build_xb_libc_cflags} -std=gnu99
build_xb_libc_src_wch_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_wch_in = libc/wchar/*.c
build_xb_libc_src_wch_ex =
build_xb_libc_src_wch_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_wch_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_tzc_cf = ${build_xb_libc_cflags} -std=gnu99
build_xb_libc_src_tzc_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_tzc_in = libc/tzcode/*.c
build_xb_libc_src_tzc_ex =
build_xb_libc_src_tzc_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_tzc_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_bon_cf = ${build_xb_libc_cflags} -std=gnu99 -I${basedir}/xbionic/libc/stdio -I${basedir}/xbionic/libm/include -DANDROID_SMP=1
build_xb_libc_src_bon_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_bon_in = libc/bionic/*.c
build_xb_libc_src_bon_ex = libc/bionic/crt*.c, libc/bionic/dl_iterate_phdr_static.c, libc/bionic/dlmalloc.c, libc/bionic/memcpy.c, libc/bionic/pthread.c
build_xb_libc_src_bon_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_bon_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_nbd_cf = ${build_xb_libc_cflags} -std=gnu99 -I${basedir}/xbionic/libm/include -I${basedir}/xbionic/libc/upstream-netbsd/libc/include
build_xb_libc_src_nbd_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_nbd_in = libc/netbsd/**/*.c
build_xb_libc_src_nbd_ex = libc/netbsd/resolv/res_random.c, libc/netbsd/resolv/res_compat.c
build_xb_libc_src_nbd_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_nbd_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)

build_xb_libc_src_nombin = libc_nomalloc.a
build_xb_libc_src_nom_cf = ${build_xb_libc_cflags} -DLIBC_STATIC -DANDROID_SMP=1 -std=gnu99 -I${basedir}/xbionic/libc/stdlib -I${basedir}/xbionic/libc
build_xb_libc_src_nom_lf = ${build_xb_libc_ldflags}
build_xb_libc_src_nom_in = libc/bionic/dl_iterate_phdr_static.c, libc/bionic/libc_init_static.cpp, libc/bionic/pthread.c, libc/bionic/pthread_create.cpp, libc/bionic/pthread_key.cpp
build_xb_libc_src_nom_ex = 
build_xb_libc_src_nom_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_nom_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)


########################
# Compile Target : XI
########################

build_xibase_src_bin     =
build_xibase_src_mk      = $(wildcard $(basedir)/src/base/src/_all/*.c)
build_xibase_src_mk     += $(wildcard $(basedir)/src/base/src/posix/*.c)
build_xibase_src_in      = _all/*.c, posix/*.c
build_xibase_src_ex      = 
build_xibase_cflags      = -I${basedir}/include
build_xibase_ldflags     = -lpthread -ldl

buildtc_xibase_src_bin   = tc_main.c
buildtc_xibase_src_mk    = $(wildcard $(basedir)/src/base/test/*.c)
buildtc_xibase_src_in    = *.c
buildtc_xibase_src_ex    = tc_main.c
buildtc_xibase_cflags    = -I${basedir}/include
buildtc_xibase_ldflags   = -lxibase


########################
# Compile Target : Ext
########################

build_ext_zlib_run       = 1
build_ext_zlib_cflags    =
build_ext_zlib_ldflags   =

build_ext_ffi_run        = 1
build_ext_ffi_cflags     =
build_ext_ffi_ldflags    =
build_ext_ffi_srcdep     = linux32

#build_ext_iconv_run      = 1
build_ext_iconv_cflags   =
build_ext_iconv_ldflags  =

build_ext_jpeg_run       = 1
build_ext_jpeg_cflags    =
build_ext_jpeg_ldflags   =

build_ext_png_run        = 1
build_ext_png_cflags     =
build_ext_png_ldflags    =

build_ext_ft_run         = 1
build_ext_ft_cflags      = -DFT2_BUILD_LIBRARY
build_ext_ft_ldflags     =

build_ext_icu4c_run      = 1
build_ext_icu4c_cflags   = -DU_STATIC_IMPLEMENTATION
build_ext_icu4c_ldf_uc   =
build_ext_icu4c_ldf_i18n =

build_ext_sqlite_run     = 1
build_ext_sqlite_cflags  =
build_ext_sqlite_ldflags = -lpthread -ldl


########################
# Compile Target : Java
########################

build_java_jvm_cflags    =
build_java_jvm_ldflags   =

build_java_jcl_cflags    =
build_java_jcl_ldflags   =

