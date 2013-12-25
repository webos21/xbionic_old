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
# File    : build_mingw32.mk                         #
# Version : 0.1.0                                    #
# Desc    : properties file for MinGW 32bit build.   #
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
build_cfg_target  = mingw32
build_cfg_mingw   = 1
#build_cfg_posix   = 1


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

build_opt_a_pre    = alib
build_opt_a_ext    = a
build_opt_so_pre   = 
build_opt_so_ext   = dll
build_opt_exe_ext  = .exe

build_opt_c        = -m32 -march=i686 -g -Wall -Wextra -Wdeclaration-after-statement -O3 -DXI_BUILD_${build_cfg_target} -D_REENTRANT -D_THREAD_SAFE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
build_opt_cxx      = -m32 -march=i686 -g -Wall -Wextra -O3 -DXI_BUILD_${build_cfg_target} -D_REENTRANT -D_THREAD_SAFE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
build_opt_fPIC     =
build_opt_ld       = -m32 -march=i686 -g -Wl,--no-undefined
build_opt_ld_so    = -shared -Wl,-soname,
build_opt_ld_rpath = -Wl,-rpath-link,
build_opt_ld_noud  = -Wl,--no-undefined
build_opt_ld_mgwcc = -static-libgcc
build_opt_ld_mgwcx = -static-libgcc -static-libstdc++


########################
# Compile Target : xbionic
########################
build_xb_cfg_arch   = win

build_xb_opt_c      = -m32 -g -O2 -Wall -Wextra -Wstrict-aliasing=2 -std=gnu99 \
		-ffunction-sections \
		-fdata-sections \
		-finline-functions -finline-limit=300 -fno-inline-functions-called-once \
		-fno-short-enums \
		-fstrict-aliasing \
		-funswitch-loops \
		-funwind-tables \
		-fstack-protector \
		-fmessage-length=0 \
		-isystem ${basedir}/xbionic/libc/arch-${build_xb_cfg_arch}/include \
		-isystem ${basedir}/xbionic/libc/include \
		-isystem ${basedir}/xbionic/libc/kernel/common \
		-isystem ${basedir}/xbionic/libc/kernel/arch-${build_xb_cfg_arch}
build_xb_opt_cxx    =  -m32 -g -O2 -Wall -Wextra -Wstrict-aliasing=2 -fno-exceptions -fno-rtti \
		-ffunction-sections \
		-fdata-sections \
		-finline-functions -finline-limit=300 -fno-inline-functions-called-once \
		-fno-short-enums \
		-fstrict-aliasing \
		-funswitch-loops \
		-funwind-tables \
		-fstack-protector \
		-fmessage-length=0 \
		-isystem ${basedir}/xbionic/libc/arch-${build_xb_cfg_arch}/include \
		-isystem ${basedir}/xbionic/libc/include \
		-isystem ${basedir}/xbionic/libc/kernel/common \
		-isystem ${basedir}/xbionic/libc/kernel/arch-${build_xb_cfg_arch}
build_xb_opt_ld     = -m32 -nostdlib

#####
# xb_libc
#####
build_xb_libc_cmn_cflags = \
	-DWITH_ERRLIST \
	-DANDROID_CHANGES \
	-D_LIBC=1 \
	-DFLOATING_POINT \
	-DINET6 \
	-DPOSIX_MISTAKE \
	-DLOG_ON_HEAP_ERROR \
	-DTM_GMTOFF=tm_gmtoff \
	-DUSG_COMPAT=1 \
	-DDEBUG \
	-DSOFTFLOAT \
	-DANDROID_SMP=1 \
	-I${basedir}/xbionic/libc/private

build_xb_libc_cmn_ldflags = -Wl,--no-undefined

build_xb_libc_cmn_incs = \
	-I${basedir}/xbionic/libc \
	-I${basedir}/xbionic/libc/stdlib \
	-I${basedir}/xbionic/libc/string \
	-I${basedir}/xbionic/libc/stdio \
	-I${basedir}/external/safe-iop/include


####
# define source file
####

build_xb_libc_sc_src =  \
	libc/arch-${build_xb_cfg_arch}/syscalls/_exit.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/_exit_thread.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__fork.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/_waitpid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__waitid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/wait4.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__sys_clone.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/execve.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__setuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getgid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/geteuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getegid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getresuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getresgid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/gettid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/readahead.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getgroups.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getpgid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getppid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getsid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setsid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setgid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__setreuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__setresuid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setresgid.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__brk.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/kill.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/tkill.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/tgkill.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__ptrace.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__set_thread_area.c, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__getpriority.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setpriority.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setrlimit.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getrlimit.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getrusage.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setgroups.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setpgid.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setregid.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/chroot.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/prctl.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/capget.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/capset.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sigaltstack.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/acct.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/read.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/write.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/pread64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/pwrite64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__open.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__openat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/close.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lseek.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__llseek.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getpid.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__mmap2.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/munmap.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mremap.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/msync.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mprotect.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/madvise.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mlock.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/munlock.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mlockall.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/munlockall.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mincore.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__ioctl.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/readv.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/writev.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__fcntl.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/flock.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fchmod.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/dup.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/pipe.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/pipe2.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/dup2.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/select.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/ftruncate.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/ftruncate64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getdents.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fsync.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fdatasync.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fchown.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sync.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__fcntl64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__fstatfs64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sendfile.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fstatat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mkdirat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fchownat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fchmodat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/renameat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fsetxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fgetxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/flistxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fremovexattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/link.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/unlink.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/unlinkat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/chdir.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mknod.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/chmod.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/chown.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lchown.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mount.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/umount2.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fstat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/stat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lstat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/mkdir.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/readlink.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/rmdir.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/rename.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__getcwd.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/access.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/faccessat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/symlink.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/fchdir.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/truncate.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lsetxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lgetxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/listxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/llistxattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/removexattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/lremovexattr.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__statfs64.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/unshare.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/pause.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/gettimeofday.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/settimeofday.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/times.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/nanosleep.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/clock_gettime.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/clock_settime.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/clock_getres.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/clock_nanosleep.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getitimer.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setitimer.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__timer_create.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__timer_settime.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__timer_gettime.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__timer_getoverrun.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__timer_delete.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/utimes.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/utimensat.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sigaction.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sigprocmask.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__sigsuspend.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__rt_sigaction.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__rt_sigprocmask.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__rt_sigtimedwait.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sigpending.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/signalfd4.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/socket.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/bind.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/connect.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/listen.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/accept.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getsockname.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getpeername.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/socketpair.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sendto.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/recvfrom.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/shutdown.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/setsockopt.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/getsockopt.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sendmsg.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/recvmsg.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_setscheduler.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_getscheduler.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_yield.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_setparam.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_getparam.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_get_priority_max.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_get_priority_min.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_rr_get_interval.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sched_setaffinity.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__sched_getaffinity.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__getcpu.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/ioprio_set.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/ioprio_get.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/uname.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/umask.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__reboot.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/__syslog.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/init_module.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/delete_module.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/klogctl.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/sysinfo.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/personality.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/perf_event_open.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/futex.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/epoll_create.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/epoll_ctl.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/epoll_wait.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/inotify_init.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/inotify_add_watch.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/inotify_rm_watch.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/poll.S, \
	libc/arch-${build_xb_cfg_arch}/syscalls/eventfd.S

build_xb_libc_common_src =  \
	${build_xb_libc_sc_src}, \
	libc/unistd/abort.c, \
	libc/unistd/alarm.c, \
	libc/unistd/exec.c, \
	libc/unistd/fnmatch.c, \
	libc/unistd/getopt_long.c, \
	libc/unistd/syslog.c, \
	libc/unistd/system.c, \
	libc/unistd/time.c, \
	libc/stdio/asprintf.c, \
	libc/stdio/clrerr.c, \
	libc/stdio/fclose.c, \
	libc/stdio/fdopen.c, \
	libc/stdio/feof.c, \
	libc/stdio/ferror.c, \
	libc/stdio/fflush.c, \
	libc/stdio/fgetc.c, \
	libc/stdio/fgetln.c, \
	libc/stdio/fgetpos.c, \
	libc/stdio/fgets.c, \
	libc/stdio/fileno.c, \
	libc/stdio/findfp.c, \
	libc/stdio/flags.c, \
	libc/stdio/fopen.c, \
	libc/stdio/fprintf.c, \
	libc/stdio/fpurge.c, \
	libc/stdio/fputc.c, \
	libc/stdio/fputs.c, \
	libc/stdio/fread.c, \
	libc/stdio/freopen.c, \
	libc/stdio/fscanf.c, \
	libc/stdio/fseek.c, \
	libc/stdio/fsetpos.c, \
	libc/stdio/ftell.c, \
	libc/stdio/funopen.c, \
	libc/stdio/fvwrite.c, \
	libc/stdio/fwalk.c, \
	libc/stdio/fwrite.c, \
	libc/stdio/getc.c, \
	libc/stdio/getchar.c, \
	libc/stdio/gets.c, \
	libc/stdio/makebuf.c, \
	libc/stdio/mktemp.c, \
	libc/stdio/printf.c, \
	libc/stdio/putc.c, \
	libc/stdio/putchar.c, \
	libc/stdio/puts.c, \
	libc/stdio/putw.c, \
	libc/stdio/refill.c, \
	libc/stdio/remove.c, \
	libc/stdio/rewind.c, \
	libc/stdio/rget.c, \
	libc/stdio/scanf.c, \
	libc/stdio/setbuf.c, \
	libc/stdio/setbuffer.c, \
	libc/stdio/setvbuf.c, \
	libc/stdio/snprintf.c, \
	libc/stdio/sprintf.c, \
	libc/stdio/sscanf.c, \
	libc/stdio/stdio.c, \
	libc/stdio/tempnam.c, \
	libc/stdio/tmpnam.c, \
	libc/stdio/ungetc.c, \
	libc/stdio/vasprintf.c, \
	libc/stdio/vfprintf.c, \
	libc/stdio/vfscanf.c, \
	libc/stdio/vprintf.c, \
	libc/stdio/vsnprintf.c, \
	libc/stdio/vsprintf.c, \
	libc/stdio/vscanf.c, \
	libc/stdio/vsscanf.c, \
	libc/stdio/wbuf.c, \
	libc/stdio/wsetup.c, \
	libc/stdlib/atexit.c, \
	libc/stdlib/ctype_.c, \
	libc/stdlib/exit.c, \
	libc/stdlib/getenv.c, \
	libc/stdlib/putenv.c, \
	libc/stdlib/qsort.c, \
	libc/stdlib/setenv.c, \
	libc/stdlib/strtod.c, \
	libc/stdlib/strtoimax.c, \
	libc/stdlib/strtol.c, \
	libc/stdlib/strtoll.c, \
	libc/stdlib/strtoul.c, \
	libc/stdlib/strtoull.c, \
	libc/stdlib/strtoumax.c, \
	libc/stdlib/tolower_.c, \
	libc/stdlib/toupper_.c, \
	libc/string/index.c, \
	libc/string/strcasecmp.c, \
	libc/string/strcat.c, \
	libc/string/strchr.c, \
	libc/string/strcspn.c, \
	libc/string/strdup.c, \
	libc/string/strlcat.c, \
	libc/string/strlcpy.c, \
	libc/string/strncat.c, \
	libc/string/strncpy.c, \
	libc/string/strpbrk.c, \
	libc/string/strrchr.c, \
	libc/string/strsep.c, \
	libc/string/strspn.c, \
	libc/string/strstr.c, \
	libc/string/strtok.c, \
	libc/wchar/wcswidth.c, \
	libc/wchar/wcsxfrm.c, \
	libc/tzcode/asctime.c, \
	libc/tzcode/difftime.c, \
	libc/tzcode/localtime.c, \
	libc/tzcode/strftime.c, \
	libc/tzcode/strptime.c, \
	libc/bionic/arc4random.c, \
	libc/bionic/atoi.c, \
	libc/bionic/atol.c, \
	libc/bionic/atoll.c, \
	libc/bionic/bindresvport.c, \
	libc/bionic/bionic_clone.c, \
	libc/bionic/clearenv.c, \
	libc/bionic/cpuacct.c, \
	libc/bionic/daemon.c, \
	libc/bionic/err.c, \
	libc/bionic/ether_aton.c, \
	libc/bionic/ether_ntoa.c, \
	libc/bionic/fcntl.c, \
	libc/bionic/fdprintf.c, \
	libc/bionic/flockfile.c, \
	libc/bionic/fork.c, \
	libc/bionic/fstatfs.c, \
	libc/bionic/ftime.c, \
	libc/bionic/ftok.c, \
	libc/bionic/fts.c, \
	libc/bionic/getdtablesize.c, \
	libc/bionic/gethostname.c, \
	libc/bionic/getpgrp.c, \
	libc/bionic/getpriority.c, \
	libc/bionic/getpt.c, \
	libc/bionic/if_indextoname.c, \
	libc/bionic/if_nametoindex.c, \
	libc/bionic/initgroups.c, \
	libc/bionic/ioctl.c, \
	libc/bionic/isatty.c, \
	libc/bionic/issetugid.c, \
	libc/bionic/ldexp.c, \
	libc/bionic/lseek64.c, \
	libc/bionic/md5.c, \
	libc/bionic/memchr.c, \
	libc/bionic/memmem.c, \
	libc/bionic/memrchr.c, \
	libc/bionic/memswap.c, \
	libc/bionic/mmap.c, \
	libc/bionic/openat.c, \
	libc/bionic/open.c, \
	libc/bionic/pathconf.c, \
	libc/bionic/perror.c, \
	libc/bionic/pread.c, \
	libc/bionic/pselect.c, \
	libc/bionic/ptsname.c, \
	libc/bionic/ptsname_r.c, \
	libc/bionic/pututline.c, \
	libc/bionic/pwrite.c, \
	libc/bionic/reboot.c, \
	libc/bionic/recv.c, \
	libc/bionic/sched_cpualloc.c, \
	libc/bionic/sched_cpucount.c, \
	libc/bionic/sched_getaffinity.c, \
	libc/bionic/sched_getcpu.c, \
	libc/bionic/semaphore.c, \
	libc/bionic/send.c, \
	libc/bionic/setegid.c, \
	libc/bionic/seteuid.c, \
	libc/bionic/setpgrp.c, \
	libc/bionic/setresuid.c, \
	libc/bionic/setreuid.c, \
	libc/bionic/setuid.c, \
	libc/bionic/sigblock.c, \
	libc/bionic/siginterrupt.c, \
	libc/bionic/siglist.c, \
	libc/bionic/signal.c, \
	libc/bionic/signame.c, \
	libc/bionic/sigsetmask.c, \
	libc/bionic/sigsuspend.c, \
	libc/bionic/sleep.c, \
	libc/bionic/statfs.c, \
	libc/bionic/strndup.c, \
	libc/bionic/strnlen.c, \
	libc/bionic/strntoimax.c, \
	libc/bionic/strntoumax.c, \
	libc/bionic/strtotimeval.c, \
	libc/bionic/system_properties.c, \
	libc/bionic/tcgetpgrp.c, \
	libc/bionic/tcsetpgrp.c, \
	libc/bionic/thread_atexit.c, \
	libc/bionic/time64.c, \
	libc/bionic/umount.c, \
	libc/bionic/unlockpt.c, \
	libc/bionic/usleep.c, \
	libc/bionic/utmp.c, \
	libc/bionic/wcscoll.c, \
	libc/netbsd/gethnamaddr.c, \
	libc/netbsd/inet/nsap_addr.c, \
	libc/netbsd/resolv/__dn_comp.c, \
	libc/netbsd/resolv/__res_close.c, \
	libc/netbsd/resolv/__res_send.c, \
	libc/netbsd/resolv/herror.c, \
	libc/netbsd/resolv/res_comp.c, \
	libc/netbsd/resolv/res_data.c, \
	libc/netbsd/resolv/res_debug.c, \
	libc/netbsd/resolv/res_init.c, \
	libc/netbsd/resolv/res_mkquery.c, \
	libc/netbsd/resolv/res_query.c, \
	libc/netbsd/resolv/res_send.c, \
	libc/netbsd/resolv/res_state.c, \
	libc/netbsd/resolv/res_cache.c, \
	libc/netbsd/net/nsdispatch.c, \
	libc/netbsd/net/getaddrinfo.c, \
	libc/netbsd/net/getnameinfo.c, \
	libc/netbsd/net/getservbyname.c, \
	libc/netbsd/net/getservent.c, \
	libc/netbsd/net/base64.c, \
	libc/netbsd/net/getservbyport.c, \
	libc/netbsd/nameser/ns_name.c, \
	libc/netbsd/nameser/ns_parse.c, \
	libc/netbsd/nameser/ns_ttl.c, \
	libc/netbsd/nameser/ns_netint.c, \
	libc/netbsd/nameser/ns_print.c, \
	libc/netbsd/nameser/ns_samedomain.c

build_xb_libc_bionic_src =  \
	libc/bionic/assert.cpp,\
	libc/bionic/brk.cpp,\
	libc/bionic/dirent.cpp,\
	libc/bionic/__errno.c,\
	libc/bionic/eventfd_read.cpp,\
	libc/bionic/eventfd_write.cpp,\
	libc/bionic/__fgets_chk.cpp,\
	libc/bionic/getauxval.cpp,\
	libc/bionic/getcwd.cpp,\
	libc/bionic/libc_init_common.cpp,\
	libc/bionic/libc_logging.cpp,\
	libc/bionic/libgen.cpp,\
	libc/bionic/__memcpy_chk.cpp,\
	libc/bionic/__memmove_chk.cpp,\
	libc/bionic/__memset_chk.cpp,\
	libc/bionic/pthread_attr.cpp,\
	libc/bionic/pthread_detach.cpp,\
	libc/bionic/pthread_equal.cpp,\
	libc/bionic/pthread_getcpuclockid.cpp,\
	libc/bionic/pthread_getschedparam.cpp,\
	libc/bionic/pthread_internals.cpp,\
	libc/bionic/pthread_join.cpp,\
	libc/bionic/pthread_kill.cpp,\
	libc/bionic/pthread_self.cpp,\
	libc/bionic/pthread_setname_np.cpp,\
	libc/bionic/pthread_setschedparam.cpp,\
	libc/bionic/pthread_sigmask.cpp,\
	libc/bionic/raise.cpp,\
	libc/bionic/sbrk.cpp,\
	libc/bionic/scandir.cpp,\
	libc/bionic/__set_errno.cpp,\
	libc/bionic/setlocale.cpp,\
	libc/bionic/signalfd.cpp,\
	libc/bionic/sigwait.cpp,\
	libc/bionic/__strcat_chk.cpp,\
	libc/bionic/__strcpy_chk.cpp,\
	libc/bionic/strerror.cpp,\
	libc/bionic/strerror_r.cpp,\
	libc/bionic/__strlcat_chk.cpp,\
	libc/bionic/__strlcpy_chk.cpp,\
	libc/bionic/__strlen_chk.cpp,\
	libc/bionic/__strncat_chk.cpp,\
	libc/bionic/__strncpy_chk.cpp,\
	libc/bionic/strsignal.cpp,\
	libc/bionic/stubs.cpp,\
	libc/bionic/sysconf.cpp,\
	libc/bionic/tdestroy.cpp,\
	libc/bionic/tmpfile.cpp,\
	libc/bionic/__umask_chk.cpp,\
	libc/bionic/__vsnprintf_chk.cpp,\
	libc/bionic/__vsprintf_chk.cpp,\
	libc/bionic/wait.cpp,\
	libc/bionic/wchar.cpp

build_xb_libc_ufreebsd_src =  \
	libc/upstream-freebsd/lib/libc/stdlib/realpath.c,\
	libc/upstream-freebsd/lib/libc/string/wcpcpy.c,\
	libc/upstream-freebsd/lib/libc/string/wcpncpy.c,\
	libc/upstream-freebsd/lib/libc/string/wcscasecmp.c,\
	libc/upstream-freebsd/lib/libc/string/wcscat.c,\
	libc/upstream-freebsd/lib/libc/string/wcschr.c,\
	libc/upstream-freebsd/lib/libc/string/wcscmp.c,\
	libc/upstream-freebsd/lib/libc/string/wcscpy.c,\
	libc/upstream-freebsd/lib/libc/string/wcscspn.c,\
	libc/upstream-freebsd/lib/libc/string/wcsdup.c,\
	libc/upstream-freebsd/lib/libc/string/wcslcat.c,\
	libc/upstream-freebsd/lib/libc/string/wcslcpy.c,\
	libc/upstream-freebsd/lib/libc/string/wcslen.c,\
	libc/upstream-freebsd/lib/libc/string/wcsncasecmp.c,\
	libc/upstream-freebsd/lib/libc/string/wcsncat.c,\
	libc/upstream-freebsd/lib/libc/string/wcsncmp.c,\
	libc/upstream-freebsd/lib/libc/string/wcsncpy.c,\
	libc/upstream-freebsd/lib/libc/string/wcsnlen.c,\
	libc/upstream-freebsd/lib/libc/string/wcspbrk.c,\
	libc/upstream-freebsd/lib/libc/string/wcsrchr.c,\
	libc/upstream-freebsd/lib/libc/string/wcsspn.c,\
	libc/upstream-freebsd/lib/libc/string/wcsstr.c,\
	libc/upstream-freebsd/lib/libc/string/wcstok.c,\
	libc/upstream-freebsd/lib/libc/string/wmemchr.c,\
	libc/upstream-freebsd/lib/libc/string/wmemcmp.c,\
	libc/upstream-freebsd/lib/libc/string/wmemcpy.c,\
	libc/upstream-freebsd/lib/libc/string/wmemmove.c,\
	libc/upstream-freebsd/lib/libc/string/wmemset.c

build_xb_libc_unetbsd_src =  \
	libc/upstream-netbsd/common/lib/libc/hash/sha1/sha1.c,\
	libc/upstream-netbsd/common/lib/libc/inet/inet_addr.c,\
	libc/upstream-netbsd/libc/compat-43/creat.c,\
	libc/upstream-netbsd/libc/gen/ftw.c,\
	libc/upstream-netbsd/libc/gen/nftw.c,\
	libc/upstream-netbsd/libc/gen/nice.c,\
	libc/upstream-netbsd/libc/gen/popen.c,\
	libc/upstream-netbsd/libc/gen/psignal.c,\
	libc/upstream-netbsd/libc/gen/setjmperr.c,\
	libc/upstream-netbsd/libc/gen/utime.c,\
	libc/upstream-netbsd/libc/inet/inet_ntoa.c,\
	libc/upstream-netbsd/libc/inet/inet_ntop.c,\
	libc/upstream-netbsd/libc/inet/inet_pton.c,\
	libc/upstream-netbsd/libc/isc/ev_streams.c,\
	libc/upstream-netbsd/libc/isc/ev_timers.c,\
	libc/upstream-netbsd/libc/regex/regcomp.c,\
	libc/upstream-netbsd/libc/regex/regerror.c,\
	libc/upstream-netbsd/libc/regex/regexec.c,\
	libc/upstream-netbsd/libc/regex/regfree.c,\
	libc/upstream-netbsd/libc/stdio/getdelim.c,\
	libc/upstream-netbsd/libc/stdio/getline.c,\
	libc/upstream-netbsd/libc/stdlib/bsearch.c,\
	libc/upstream-netbsd/libc/stdlib/div.c,\
	libc/upstream-netbsd/libc/stdlib/drand48.c,\
	libc/upstream-netbsd/libc/stdlib/erand48.c,\
	libc/upstream-netbsd/libc/stdlib/jrand48.c,\
	libc/upstream-netbsd/libc/stdlib/ldiv.c,\
	libc/upstream-netbsd/libc/stdlib/lldiv.c,\
	libc/upstream-netbsd/libc/stdlib/lrand48.c,\
	libc/upstream-netbsd/libc/stdlib/mrand48.c,\
	libc/upstream-netbsd/libc/stdlib/nrand48.c,\
	libc/upstream-netbsd/libc/stdlib/_rand48.c,\
	libc/upstream-netbsd/libc/stdlib/seed48.c,\
	libc/upstream-netbsd/libc/stdlib/srand48.c,\
	libc/upstream-netbsd/libc/stdlib/tdelete.c,\
	libc/upstream-netbsd/libc/stdlib/tfind.c,\
	libc/upstream-netbsd/libc/stdlib/tsearch.c,\
	libc/upstream-netbsd/libc/string/memccpy.c,\
	libc/upstream-netbsd/libc/string/strcasestr.c,\
	libc/upstream-netbsd/libc/string/strcoll.c,\
	libc/upstream-netbsd/libc/string/strxfrm.c,\
	libc/upstream-netbsd/libc/unistd/killpg.c

# libc : add arch-common, arch.mk, and cpu_variant
build_xb_libc_r_common_src =  \
	${build_xb_libc_common_src}, \
	libc/bionic/pthread-atfork.c, \
	libc/bionic/pthread-rwlocks.c, \
	libc/bionic/pthread-timers.c, \
	libc/bionic/ptrace.c, \
	libc/string/strcpy.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/clone.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/_exit_with_stack_teardown.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/futex_x86.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/__get_sp.S, \
	libc/arch-${build_xb_cfg_arch}/bionic/__get_tls.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/_setjmp.S, \
	libc/arch-${build_xb_cfg_arch}/bionic/setjmp.S, \
	libc/arch-${build_xb_cfg_arch}/bionic/__set_tls.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/sigsetjmp.S, \
	libc/arch-${build_xb_cfg_arch}/bionic/syscall.c, \
	libc/arch-${build_xb_cfg_arch}/bionic/vfork.c, \
	libc/arch-${build_xb_cfg_arch}/string/bcopy_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/bzero_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/ffs.S, \
	libc/arch-${build_xb_cfg_arch}/string/memcmp_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/memcpy_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/memmove_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/memset_wrapper.c, \
	libc/arch-${build_xb_cfg_arch}/string/strcmp_wrapper.S, \
	libc/arch-${build_xb_cfg_arch}/string/strlen_wrapper.S, \
	libc/arch-${build_xb_cfg_arch}/string/strncmp_wrapper.S

# libc : static common
build_xb_libc_s_common_src =  \
	libc/bionic/pthread.c, \
	libc/bionic/pthread_create.cpp, \
	libc/bionic/pthread_key.cpp, \

# libc : arch static
build_xb_libc_arch_static_src =  \
	libc/bionic/dl_iterate_phdr_static.c

# libc : arch dynamic - x86 has no target file
build_xb_libc_arch_dynamic_src =


####
# CRT (libc run-time)
####
build_xb_libc_crt_bin     =
build_xb_libc_crt_cflags  = -DUSE_SSE2=1 -DUSE_SSE3=1 -DPLATFORM_SDK_VERSION=18 \
	-I${basedir}/xbionic/libc/include \
    -I${basedir}/xbionic/libc/private \
    -I${basedir}/xbionic/libc/arch-${build_xb_cfg_arch}/include
build_xb_libc_crt_ldflags = 
build_xb_libc_crt_src_in  = libc/bionic/crtbrand.c, libc/arch-${build_xb_cfg_arch}/bionic/crt*.S, libc/arch-${build_xb_cfg_arch}/bionic/crt*.c
build_xb_libc_crt_src_ex  = 
build_xb_libc_crt_src_mk  = ${build_xb_libc_crt_src_in}

####
# libdl.so
####
build_xb_libdl_bin        = dl.dll
build_xb_libdl_cflags     = ${build_xb_libc_cmn_cflags}
build_xb_libdl_ldflags    = -Wl,--exclude-libs=libgcc.a -Wl,--exclude-libs=libgcc_eh.a
build_xb_libdl_src_in     = libdl/libdl.c
build_xb_libdl_src_ex     = 
build_xb_libdl_src_mk     = ${build_xb_libdl_src_in}

####
# libbionic_ssp.a
####
build_xb_libc_ssp_bin     = libbionic_ssp.a
build_xb_libc_ssp_cflags  = ${build_xb_libc_cmn_cflags} -fno-stack-protector -Werror
build_xb_libc_ssp_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_ssp_src_in  = libc/bionic/__stack_chk_fail.cpp
build_xb_libc_ssp_src_ex  = 
build_xb_libc_ssp_src_mk  = ${build_xb_libc_ssp_src_in}

####
# libc_freebsd.a
####
build_xb_libc_ufb_bin     = libc_freebsd.a
build_xb_libc_ufb_cflags  = ${build_xb_libc_cmn_cflags} \
	-D_WCTYPE_T_DEFINED \
	-I${basedir}/xbionic/libc/upstream-freebsd \
	-include ${basedir}/xbionic/libc/upstream-freebsd/freebsd-compat.h
build_xb_libc_ufb_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_ufb_src_in  = ${build_xb_libc_ufreebsd_src}
build_xb_libc_ufb_src_ex  = 
build_xb_libc_ufb_src_mk  = ${build_xb_libc_ufb_src_in}

####
# libc_netbsd.a
####
build_xb_libc_unb_bin     = libc_netbsd.a
build_xb_libc_unb_cflags  = ${build_xb_libc_cmn_cflags} \
	-I${basedir}/xbionic/libc/stdio \
	-I${basedir}/xbionic/libm/include \
	-I${basedir}/xbionic/libc/upstream-netbsd \
	-I${basedir}/xbionic/libc/upstream-netbsd/libc/include \
	-include ${basedir}/xbionic/libc/upstream-netbsd/netbsd-compat.h
build_xb_libc_unb_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_unb_src_in  = ${build_xb_libc_unetbsd_src}
build_xb_libc_unb_src_ex  =
build_xb_libc_unb_src_mk  = $(build_xb_libc_unb_src_in)

####
# libc_bionic.a
####
build_xb_libc_bnx_bin     = libc_bionic.a
build_xb_libc_bnx_cflags  = ${build_xb_libc_cmn_cflags} -Werror ${build_xb_libc_cmn_incs} \
	-D_WCTYPE_T_DEFINED \
	-I${basedir}/external/android/system/core/include
build_xb_libc_bnx_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_bnx_src_in  = ${build_xb_libc_bionic_src}
build_xb_libc_bnx_src_ex  = 
build_xb_libc_bnx_src_mk  = ${build_xb_libc_bnx_src_in}

####
# libc_common.a
####
build_xb_libc_com_bin     = libc_common.a
build_xb_libc_com_cflags  = ${build_xb_libc_cmn_cflags} ${build_xb_libc_cmn_incs} \
	-D_WCTYPE_T_DEFINED \
	-I${basedir}/lib/${build_cfg_target}/include \
	-I${basedir}/xbionic/libc/upstream-netbsd/libc/include \
	-I${basedir}/xbionic/libm/include
build_xb_libc_com_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_com_src_in  = libc/arch-${build_xb_cfg_arch}/_ntdll/ntdll.c, ${build_xb_libc_r_common_src}
build_xb_libc_com_src_ex  = 
build_xb_libc_com_src_mk  = ${build_xb_libc_com_src_in}

####
# libc_nomalloc.a
####
build_xb_libc_nml_bin     = libc_nomalloc.a
build_xb_libc_nml_cflags  = ${build_xb_libc_cmn_cflags} -DLIBC_STATIC ${build_xb_libc_cmn_incs}
build_xb_libc_nml_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_nml_src_in  = ${build_xb_libc_arch_static_src}, ${build_xb_libc_s_common_src}, libc/bionic/libc_init_static.cpp
build_xb_libc_nml_src_ex  = 
build_xb_libc_nml_src_mk  = ${build_xb_libc_nml_src_in}

####
# libc.a
####
build_xb_libc_lca_bin     = libc.a
build_xb_libc_lca_cflags  = ${build_xb_libc_cmn_cflags} -DLIBC_STATIC ${build_xb_libc_cmn_incs}
build_xb_libc_lca_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_lca_src_in  = ${build_xb_libc_arch_static_src}, ${build_xb_libc_s_common_src}, \
		libc/bionic/dlmalloc.c, \
		libc/bionic/malloc_debug_common.cpp, \
		libc/bionic/libc_init_static.cpp
build_xb_libc_lca_src_ex  = 
build_xb_libc_lca_src_mk  = ${build_xb_libc_lca_src_in}

####
# libc.so
####
build_xb_libc_lcs_bin     = c.dll
build_xb_libc_lcs_cflags  = ${build_xb_libc_cmn_cflags} -DPTHREAD_DEBUG -DPTHREAD_DEBUG_ENABLED=0 ${build_xb_libc_cmn_incs}
build_xb_libc_lcs_ldflags = ${build_xb_libc_cmn_ldflags} \
		${basedir}/lib/${build_cfg_target}/libgcc.a \
		${basedir}/lib/${build_cfg_target}/libgcc_eh.a \
		"C:/Program Files/Microsoft SDKs/Windows/v7.1/Lib/Kernel32.lib"
#		/home/appos/gitrepo/android-x86/prebuilts/gcc/linux-x86/x86/i686-linux-android-4.7/lib/gcc/i686-linux-android/4.7/libgcc.a
build_xb_libc_lcs_src_in  = ${build_xb_libc_arch_dynamic_src}, ${build_xb_libc_s_common_src}, \
		libc/bionic/dlmalloc.c, \
		libc/bionic/malloc_debug_common.cpp, \
		libc/bionic/debug_mapinfo.cpp, \
		libc/bionic/debug_stacktrace.cpp, \
		libc/bionic/pthread_debug.cpp, \
		libc/bionic/libc_init_dynamic.cpp
build_xb_libc_lcs_src_ex  = 
build_xb_libc_lcs_src_mk  = ${build_xb_libc_lcs_src_in}

####
# libc_malloc_debug_leak.so
####
build_xb_libc_mdl_bin     = c_malloc_debug_leak.dll
build_xb_libc_mdl_cflags  = ${build_xb_libc_cmn_cflags} -DMALLOC_LEAK_CHECK
build_xb_libc_mdl_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_mdl_src_in  = \
		libc/bionic/debug_mapinfo.cpp, \
		libc/bionic/debug_stacktrace.cpp, \
		libc/bionic/malloc_debug_leak.cpp, \
		libc/bionic/malloc_debug_check.cpp
build_xb_libc_mdl_src_ex  = 
build_xb_libc_mdl_src_mk  = ${build_xb_libc_mdl_src_in}

####
# libc_malloc_debug_qemu.so
####
build_xb_libc_mdq_bin     = c_malloc_debug_qemu.dll
build_xb_libc_mdq_cflags  = ${build_xb_libc_cmn_cflags} -DMALLOC_QEMU_INSTRUMENT
build_xb_libc_mdq_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_mdq_src_in  = libc/bionic/malloc_debug_qemu.cpp
build_xb_libc_mdq_src_ex  = 
build_xb_libc_mdq_src_mk  = ${build_xb_libc_mdq_src_in}

####
# libm.a
####
build_xb_libm_a_bin       = libm.a
build_xb_libm_a_cflags    = ${build_xb_libc_cmn_cflags} \
		-DFLT_EVAL_METHOD=0 \
		-I${basedir}/xbionic/libm \
		-I${basedir}/xbionic/libm/include \
		-I${basedir}/xbionic/libm/include/i387 \
		-I${basedir}/xbionic/libm/i386 \
		-I${basedir}/xbionic/libm/upstream-freebsd/lib/msun/src
build_xb_libm_a_ldflags   =
build_xb_libm_a_src_in    = \
    libm/digittoint.c, \
    libm/fpclassify.c, \
    libm/isinf.c, \
    libm/sincos.c, \
    libm/fake_long_double.c, \
	libm/i387/fenv.c, \
	libm/upstream-freebsd/lib/msun/bsdsrc/b_exp.c, \
	libm/upstream-freebsd/lib/msun/bsdsrc/b_log.c, \
	libm/upstream-freebsd/lib/msun/bsdsrc/b_tgamma.c, \
	libm/upstream-freebsd/lib/msun/src/e_acos.c, \
	libm/upstream-freebsd/lib/msun/src/e_acosf.c, \
	libm/upstream-freebsd/lib/msun/src/e_acosh.c, \
	libm/upstream-freebsd/lib/msun/src/e_acoshf.c, \
	libm/upstream-freebsd/lib/msun/src/e_asin.c, \
	libm/upstream-freebsd/lib/msun/src/e_asinf.c, \
	libm/upstream-freebsd/lib/msun/src/e_atan2.c, \
	libm/upstream-freebsd/lib/msun/src/e_atan2f.c, \
	libm/upstream-freebsd/lib/msun/src/e_atanh.c, \
	libm/upstream-freebsd/lib/msun/src/e_atanhf.c, \
	libm/upstream-freebsd/lib/msun/src/e_cosh.c, \
	libm/upstream-freebsd/lib/msun/src/e_coshf.c, \
	libm/upstream-freebsd/lib/msun/src/e_exp.c, \
	libm/upstream-freebsd/lib/msun/src/e_expf.c, \
	libm/upstream-freebsd/lib/msun/src/e_fmod.c, \
	libm/upstream-freebsd/lib/msun/src/e_fmodf.c, \
	libm/upstream-freebsd/lib/msun/src/e_gamma.c, \
	libm/upstream-freebsd/lib/msun/src/e_gammaf.c, \
	libm/upstream-freebsd/lib/msun/src/e_gammaf_r.c, \
	libm/upstream-freebsd/lib/msun/src/e_gamma_r.c, \
	libm/upstream-freebsd/lib/msun/src/e_hypot.c, \
	libm/upstream-freebsd/lib/msun/src/e_hypotf.c, \
	libm/upstream-freebsd/lib/msun/src/e_j0.c, \
	libm/upstream-freebsd/lib/msun/src/e_j0f.c, \
	libm/upstream-freebsd/lib/msun/src/e_j1.c, \
	libm/upstream-freebsd/lib/msun/src/e_j1f.c, \
	libm/upstream-freebsd/lib/msun/src/e_jn.c, \
	libm/upstream-freebsd/lib/msun/src/e_jnf.c, \
	libm/upstream-freebsd/lib/msun/src/e_lgamma.c, \
	libm/upstream-freebsd/lib/msun/src/e_lgammaf.c, \
	libm/upstream-freebsd/lib/msun/src/e_lgammaf_r.c, \
	libm/upstream-freebsd/lib/msun/src/e_lgamma_r.c, \
	libm/upstream-freebsd/lib/msun/src/e_log10.c, \
	libm/upstream-freebsd/lib/msun/src/e_log10f.c, \
	libm/upstream-freebsd/lib/msun/src/e_log2.c, \
	libm/upstream-freebsd/lib/msun/src/e_log2f.c, \
	libm/upstream-freebsd/lib/msun/src/e_log.c, \
	libm/upstream-freebsd/lib/msun/src/e_logf.c, \
	libm/upstream-freebsd/lib/msun/src/e_pow.c, \
	libm/upstream-freebsd/lib/msun/src/e_powf.c, \
	libm/upstream-freebsd/lib/msun/src/e_remainder.c, \
	libm/upstream-freebsd/lib/msun/src/e_remainderf.c, \
	libm/upstream-freebsd/lib/msun/src/e_rem_pio2.c, \
	libm/upstream-freebsd/lib/msun/src/e_rem_pio2f.c, \
	libm/upstream-freebsd/lib/msun/src/e_scalb.c, \
	libm/upstream-freebsd/lib/msun/src/e_scalbf.c, \
	libm/upstream-freebsd/lib/msun/src/e_sinh.c, \
	libm/upstream-freebsd/lib/msun/src/e_sinhf.c, \
	libm/upstream-freebsd/lib/msun/src/e_sqrt.c, \
	libm/upstream-freebsd/lib/msun/src/e_sqrtf.c, \
	libm/upstream-freebsd/lib/msun/src/k_cos.c, \
	libm/upstream-freebsd/lib/msun/src/k_cosf.c, \
	libm/upstream-freebsd/lib/msun/src/k_exp.c, \
	libm/upstream-freebsd/lib/msun/src/k_expf.c, \
	libm/upstream-freebsd/lib/msun/src/k_rem_pio2.c, \
	libm/upstream-freebsd/lib/msun/src/k_sin.c, \
	libm/upstream-freebsd/lib/msun/src/k_sinf.c, \
	libm/upstream-freebsd/lib/msun/src/k_tan.c, \
	libm/upstream-freebsd/lib/msun/src/k_tanf.c, \
	libm/upstream-freebsd/lib/msun/src/s_asinh.c, \
	libm/upstream-freebsd/lib/msun/src/s_asinhf.c, \
	libm/upstream-freebsd/lib/msun/src/s_atan.c, \
	libm/upstream-freebsd/lib/msun/src/s_atanf.c, \
	libm/upstream-freebsd/lib/msun/src/s_carg.c, \
	libm/upstream-freebsd/lib/msun/src/s_cargf.c, \
	libm/upstream-freebsd/lib/msun/src/s_cbrt.c, \
	libm/upstream-freebsd/lib/msun/src/s_cbrtf.c, \
	libm/upstream-freebsd/lib/msun/src/s_ccosh.c, \
	libm/upstream-freebsd/lib/msun/src/s_ccoshf.c, \
	libm/upstream-freebsd/lib/msun/src/s_ceil.c, \
	libm/upstream-freebsd/lib/msun/src/s_ceilf.c, \
	libm/upstream-freebsd/lib/msun/src/s_cexp.c, \
	libm/upstream-freebsd/lib/msun/src/s_cexpf.c, \
	libm/upstream-freebsd/lib/msun/src/s_cimag.c, \
	libm/upstream-freebsd/lib/msun/src/s_cimagf.c, \
	libm/upstream-freebsd/lib/msun/src/s_conj.c, \
	libm/upstream-freebsd/lib/msun/src/s_conjf.c, \
	libm/upstream-freebsd/lib/msun/src/s_copysign.c, \
	libm/upstream-freebsd/lib/msun/src/s_copysignf.c, \
	libm/upstream-freebsd/lib/msun/src/s_cos.c, \
	libm/upstream-freebsd/lib/msun/src/s_cosf.c, \
	libm/upstream-freebsd/lib/msun/src/s_cproj.c, \
	libm/upstream-freebsd/lib/msun/src/s_cprojf.c, \
	libm/upstream-freebsd/lib/msun/src/s_creal.c, \
	libm/upstream-freebsd/lib/msun/src/s_crealf.c, \
	libm/upstream-freebsd/lib/msun/src/s_csinh.c, \
	libm/upstream-freebsd/lib/msun/src/s_csinhf.c, \
	libm/upstream-freebsd/lib/msun/src/s_csqrt.c, \
	libm/upstream-freebsd/lib/msun/src/s_csqrtf.c, \
	libm/upstream-freebsd/lib/msun/src/s_ctanh.c, \
	libm/upstream-freebsd/lib/msun/src/s_ctanhf.c, \
	libm/upstream-freebsd/lib/msun/src/s_erf.c, \
	libm/upstream-freebsd/lib/msun/src/s_erff.c, \
	libm/upstream-freebsd/lib/msun/src/s_exp2.c, \
	libm/upstream-freebsd/lib/msun/src/s_exp2f.c, \
	libm/upstream-freebsd/lib/msun/src/s_expm1.c, \
	libm/upstream-freebsd/lib/msun/src/s_expm1f.c, \
	libm/upstream-freebsd/lib/msun/src/s_fabs.c, \
	libm/upstream-freebsd/lib/msun/src/s_fabsf.c, \
	libm/upstream-freebsd/lib/msun/src/s_fdim.c, \
	libm/upstream-freebsd/lib/msun/src/s_finite.c, \
	libm/upstream-freebsd/lib/msun/src/s_finitef.c, \
	libm/upstream-freebsd/lib/msun/src/s_floor.c, \
	libm/upstream-freebsd/lib/msun/src/s_floorf.c, \
	libm/upstream-freebsd/lib/msun/src/s_fma.c, \
	libm/upstream-freebsd/lib/msun/src/s_fmaf.c, \
	libm/upstream-freebsd/lib/msun/src/s_fmax.c, \
	libm/upstream-freebsd/lib/msun/src/s_fmaxf.c, \
	libm/upstream-freebsd/lib/msun/src/s_fmin.c, \
	libm/upstream-freebsd/lib/msun/src/s_fminf.c, \
	libm/upstream-freebsd/lib/msun/src/s_frexp.c, \
	libm/upstream-freebsd/lib/msun/src/s_frexpf.c, \
	libm/upstream-freebsd/lib/msun/src/s_ilogb.c, \
	libm/upstream-freebsd/lib/msun/src/s_ilogbf.c, \
	libm/upstream-freebsd/lib/msun/src/s_isfinite.c, \
	libm/upstream-freebsd/lib/msun/src/s_isnan.c, \
	libm/upstream-freebsd/lib/msun/src/s_isnormal.c, \
	libm/upstream-freebsd/lib/msun/src/s_llrint.c, \
	libm/upstream-freebsd/lib/msun/src/s_llrintf.c, \
	libm/upstream-freebsd/lib/msun/src/s_llround.c, \
	libm/upstream-freebsd/lib/msun/src/s_llroundf.c, \
	libm/upstream-freebsd/lib/msun/src/s_log1p.c, \
	libm/upstream-freebsd/lib/msun/src/s_log1pf.c, \
	libm/upstream-freebsd/lib/msun/src/s_logb.c, \
	libm/upstream-freebsd/lib/msun/src/s_logbf.c, \
	libm/upstream-freebsd/lib/msun/src/s_lrint.c, \
	libm/upstream-freebsd/lib/msun/src/s_lrintf.c, \
	libm/upstream-freebsd/lib/msun/src/s_lround.c, \
	libm/upstream-freebsd/lib/msun/src/s_lroundf.c, \
	libm/upstream-freebsd/lib/msun/src/s_modf.c, \
	libm/upstream-freebsd/lib/msun/src/s_modff.c, \
	libm/upstream-freebsd/lib/msun/src/s_nan.c, \
	libm/upstream-freebsd/lib/msun/src/s_nearbyint.c, \
	libm/upstream-freebsd/lib/msun/src/s_nextafter.c, \
	libm/upstream-freebsd/lib/msun/src/s_nextafterf.c, \
	libm/upstream-freebsd/lib/msun/src/s_nexttowardf.c, \
	libm/upstream-freebsd/lib/msun/src/s_remquo.c, \
	libm/upstream-freebsd/lib/msun/src/s_remquof.c, \
	libm/upstream-freebsd/lib/msun/src/s_rint.c, \
	libm/upstream-freebsd/lib/msun/src/s_rintf.c, \
	libm/upstream-freebsd/lib/msun/src/s_round.c, \
	libm/upstream-freebsd/lib/msun/src/s_roundf.c, \
	libm/upstream-freebsd/lib/msun/src/s_scalbln.c, \
	libm/upstream-freebsd/lib/msun/src/s_scalbn.c, \
	libm/upstream-freebsd/lib/msun/src/s_scalbnf.c, \
	libm/upstream-freebsd/lib/msun/src/s_signbit.c, \
	libm/upstream-freebsd/lib/msun/src/s_signgam.c, \
	libm/upstream-freebsd/lib/msun/src/s_significand.c, \
	libm/upstream-freebsd/lib/msun/src/s_significandf.c, \
	libm/upstream-freebsd/lib/msun/src/s_sin.c, \
	libm/upstream-freebsd/lib/msun/src/s_sinf.c, \
	libm/upstream-freebsd/lib/msun/src/s_tan.c, \
	libm/upstream-freebsd/lib/msun/src/s_tanf.c, \
	libm/upstream-freebsd/lib/msun/src/s_tanh.c, \
	libm/upstream-freebsd/lib/msun/src/s_tanhf.c, \
	libm/upstream-freebsd/lib/msun/src/s_tgammaf.c, \
	libm/upstream-freebsd/lib/msun/src/s_trunc.c, \
	libm/upstream-freebsd/lib/msun/src/s_truncf.c, \
	libm/upstream-freebsd/lib/msun/src/w_cabs.c, \
	libm/upstream-freebsd/lib/msun/src/w_cabsf.c, \
	libm/upstream-freebsd/lib/msun/src/w_drem.c, \
	libm/upstream-freebsd/lib/msun/src/w_dremf.c
build_xb_libm_a_src_ex    =
build_xb_libm_a_src_mk    = ${build_xb_libm_a_src_in}

####
# libm.so
####
build_xb_libm_so_bin       = m.dll
build_xb_libm_so_cflags    =
build_xb_libm_so_ldflags   = ${basedir}/lib/${build_cfg_target}/libgcc.a -Wl,--no-undefined
build_xb_libm_so_src_in    = 
build_xb_libm_so_src_ex    = 
build_xb_libm_so_src_mk    =

####
# libstdc++.a
####
build_xb_libscx_a_bin      = libstdc++.a
build_xb_libscx_a_cflags   = ${build_xb_libc_cmn_cflags} -I${basedir}/xbionic/libstdc++/include \
	-I${basedir}/xbionic/libc
build_xb_libscx_a_ldflags  =
build_xb_libscx_a_src_in   = \
	libstdc++/src/one_time_construction.cpp, \
	libstdc++/src/new.cpp, \
	libstdc++/src/pure_virtual.cpp, \
	libstdc++/src/typeinfo.cpp
build_xb_libscx_a_src_ex   = 
build_xb_libscx_a_src_mk   = ${build_xb_libscx_a_src_in}

####
# libstdc++.so
####
build_xb_libscx_so_bin     = stdc++.dll
build_xb_libscx_so_cflags  =
build_xb_libscx_so_ldflags = ${basedir}/lib/${build_cfg_target}/libgcc.a -Wl,--no-undefined
build_xb_libscx_so_src_in  = 
build_xb_libscx_so_src_ex  = 
build_xb_libscx_so_src_mk  =

####
# libthread_db.a
####
build_xb_libtdb_a_bin      = libthread_db.a
build_xb_libtdb_a_cflags   = ${build_xb_libc_cmn_cflags} -I${basedir}/xbionic/libthread_db/include
build_xb_libtdb_a_ldflags  =
build_xb_libtdb_a_src_in   = libthread_db/libthread_db.c
build_xb_libtdb_a_src_ex   = 
build_xb_libtdb_a_src_mk   = ${build_xb_libtdb_a_src_in}

####
# libthread_db.so
####
build_xb_libtdb_so_bin     = thread_db.dll
build_xb_libtdb_so_cflags  =
build_xb_libtdb_so_ldflags = ${basedir}/lib/${build_cfg_target}/libgcc.a
build_xb_libtdb_so_src_in  = 
build_xb_libtdb_so_src_ex  = 
build_xb_libtdb_so_src_mk  =

####
# linker
####
build_xb_linker_bin        = linker.exe
build_xb_linker_cflags     = \
		-m32 -g -O2 -Wall -Wextra -Werror -fno-exceptions \
		-ffunction-sections \
		-finline-functions -finline-limit=300 -fno-inline-functions-called-once \
		-fno-short-enums \
		-fstrict-aliasing \
		-funswitch-loops \
		-funwind-tables \
		-fmessage-length=0 \
		-isystem ${basedir}/xbionic/libc/arch-${build_xb_cfg_arch}/include \
		-isystem ${basedir}/xbionic/libc/include \
		-isystem ${basedir}/xbionic/libc/kernel/common \
		-isystem ${basedir}/xbionic/libc/kernel/arch-${build_xb_cfg_arch} \
		-fno-stack-protector \
        -Wstrict-overflow=5 \
        -fvisibility=hidden \
        -DANDROID_X86_LINKER \
        -I${basedir}/xbionic/libc
build_xb_linker_ldflags    = \
		-Wl,-Bsymbolic \
		-Wl,--warn-shared-textrel \
		-Wl,--no-export-dynamic \
		-Wl,--gc-sections \
		-nostdlib \
		-Bstatic \
		-shared -Wl,--exclude-libs,ALL -Wl,--no-undefined \
		${basedir}/lib/${build_cfg_target}/libgcc.a \
		-lkernel32
build_xb_linker_src_in     = \
    linker/arch/${build_xb_cfg_arch}/begin.c, \
    linker/debugger.cpp, \
    linker/dlfcn.cpp, \
    linker/linker.cpp, \
    linker/linker_environ.cpp, \
    linker/linker_phdr.cpp, \
    linker/rt.cpp
build_xb_linker_src_ex     = 
build_xb_linker_src_mk     = ${build_xb_linker_src_in}


########################
# Compile Target : XI
########################

build_xibase_src_bin    =
build_xibase_src_mk     = $(wildcard $(basedir)/src/base/src/_all/*.c)
build_xibase_src_mk    += $(wildcard $(basedir)/src/base/src/win32/*.c)
build_xibase_src_in     = _all/*.c, win32/*.c
build_xibase_src_ex     = 
build_xibase_cflags     = -I${basedir}/include
build_xibase_ldflags    = -lws2_32 -lmswsock -luserenv ${basedir}/src/base/xibase.def

buildtc_xibase_src_bin  = tc_main.c
buildtc_xibase_src_mk     = $(wildcard $(basedir)/src/base/test/*.c)
buildtc_xibase_src_in   = *.c
buildtc_xibase_src_ex   = tc_main.c
buildtc_xibase_cflags   = -I${basedir}/include
buildtc_xibase_ldflags  = -lxibase ${basedir}/src/base/xibasetest.def


########################
# Compile Target : Ext
########################

build_ext_zlib_run       = 1
build_ext_zlib_cflags    =
build_ext_zlib_ldflags   = ${basedir}/external/zlib/zlib.def

build_ext_ffi_run        = 1
build_ext_ffi_cflags     =
build_ext_ffi_ldflags    = ${basedir}/external/libffi/ffi32.def
build_ext_ffi_srcdep     = win32

#build_ext_iconv_run      = 1
build_ext_iconv_cflags   =
build_ext_iconv_ldflags  = ${basedir}/external/libiconv/iconv.def

build_ext_jpeg_run       = 1
build_ext_jpeg_cflags    =
build_ext_jpeg_ldflags   = ${basedir}/external/libjpeg/jpeg.def

build_ext_png_run        = 1
build_ext_png_cflags     =
build_ext_png_ldflags    = ${basedir}/external/libpng/png.def

build_ext_ft_run         = 1
build_ext_ft_cflags      = -DFT2_BUILD_LIBRARY
build_ext_ft_ldflags     = ${basedir}/external/freetype/freetype.def

build_ext_icu4c_run      = 1
build_ext_icu4c_cflags   = -DU_WINDOWS -DU_STATIC_IMPLEMENTATION
build_ext_icu4c_ldf_uc   = ${basedir}/external/icu4c/icuuc.def
build_ext_icu4c_ldf_i18n = ${basedir}/external/icu4c/icui18n.def

build_ext_sqlite_run     = 1
build_ext_sqlite_cflags  =
build_ext_sqlite_ldflags = ${basedir}/external/sqlite/sqlite3.def


########################
# Compile Target : Java
########################

build_java_jvm_cflags    =
build_java_jvm_ldflags   =

build_java_jcl_cflags    =
build_java_jcl_ldflags   = ${basedir}/java/jcl/jcl.def

