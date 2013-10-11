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
build_xb_opt_c      = -m32 -g -O2 -Wall -Wextra -Wstrict-aliasing=2 -std=gnu99 \
		-fPIC -fPIE \
		-ffunction-sections \
		-finline-functions -finline-limit=300 -fno-inline-functions-called-once \
		-fno-short-enums \
		-fstrict-aliasing \
		-funswitch-loops \
		-funwind-tables \
		-fstack-protector \
		-fmessage-length=0 \
		-Wa,--noexecstack \
		-isystem ${basedir}/xbionic/libc/arch-${build_cfg_arch}/include \
		-isystem ${basedir}/xbionic/libc/include \
		-isystem ${basedir}/xbionic/libc/kernel/common \
		-isystem ${basedir}/xbionic/libc/kernel/arch-${build_cfg_arch}
build_xb_opt_cxx    =  -m32 -g -O2 -Wall -Wextra -Wstrict-aliasing=2 -fno-exceptions \
		-fPIC -fPIE \
		-ffunction-sections \
		-finline-functions -finline-limit=300 -fno-inline-functions-called-once \
		-fno-short-enums \
		-fstrict-aliasing \
		-funswitch-loops \
		-funwind-tables \
		-fstack-protector \
		-fmessage-length=0 \
		-Wa,--noexecstack \
		-isystem ${basedir}/xbionic/libc/arch-${build_cfg_arch}/include \
		-isystem ${basedir}/xbionic/libc/include \
		-isystem ${basedir}/xbionic/libc/kernel/common \
		-isystem ${basedir}/xbionic/libc/kernel/arch-${build_cfg_arch}
build_xb_opt_ld     = -m32 -Wl,--no-undefined -nostdlib

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

build_xb_libc_cmn_ldflags =

build_xb_libc_cmn_incs = \
	-I${basedir}/xbionic/libc \
	-I${basedir}/xbionic/libc/stdlib \
	-I${basedir}/xbionic/libc/string \
	-I${basedir}/xbionic/libc/stdio \
	-I${basedir}/external/safe-iop/include


####
# define source file
####

build_xb_syscall_src =  \
	libc/arch-x86/syscalls/_exit.S, \
	libc/arch-x86/syscalls/_exit_thread.S, \
	libc/arch-x86/syscalls/__fork.S, \
	libc/arch-x86/syscalls/_waitpid.S, \
	libc/arch-x86/syscalls/__waitid.S, \
	libc/arch-x86/syscalls/wait4.S, \
	libc/arch-x86/syscalls/__sys_clone.S, \
	libc/arch-x86/syscalls/execve.S, \
	libc/arch-x86/syscalls/__setuid.S, \
	libc/arch-x86/syscalls/getuid.S, \
	libc/arch-x86/syscalls/getgid.S, \
	libc/arch-x86/syscalls/geteuid.S, \
	libc/arch-x86/syscalls/getegid.S, \
	libc/arch-x86/syscalls/getresuid.S, \
	libc/arch-x86/syscalls/getresgid.S, \
	libc/arch-x86/syscalls/gettid.S, \
	libc/arch-x86/syscalls/readahead.S, \
	libc/arch-x86/syscalls/getgroups.S, \
	libc/arch-x86/syscalls/getpgid.S, \
	libc/arch-x86/syscalls/getppid.S, \
	libc/arch-x86/syscalls/getsid.S, \
	libc/arch-x86/syscalls/setsid.S, \
	libc/arch-x86/syscalls/setgid.S, \
	libc/arch-x86/syscalls/__setreuid.S, \
	libc/arch-x86/syscalls/__setresuid.S, \
	libc/arch-x86/syscalls/setresgid.S, \
	libc/arch-x86/syscalls/__brk.S, \
	libc/arch-x86/syscalls/kill.S, \
	libc/arch-x86/syscalls/tkill.S, \
	libc/arch-x86/syscalls/tgkill.S, \
	libc/arch-x86/syscalls/__ptrace.S, \
	libc/arch-x86/syscalls/__set_thread_area.S, \
	libc/arch-x86/syscalls/__getpriority.S, \
	libc/arch-x86/syscalls/setpriority.S, \
	libc/arch-x86/syscalls/setrlimit.S, \
	libc/arch-x86/syscalls/getrlimit.S, \
	libc/arch-x86/syscalls/getrusage.S, \
	libc/arch-x86/syscalls/setgroups.S, \
	libc/arch-x86/syscalls/setpgid.S, \
	libc/arch-x86/syscalls/setregid.S, \
	libc/arch-x86/syscalls/chroot.S, \
	libc/arch-x86/syscalls/prctl.S, \
	libc/arch-x86/syscalls/capget.S, \
	libc/arch-x86/syscalls/capset.S, \
	libc/arch-x86/syscalls/sigaltstack.S, \
	libc/arch-x86/syscalls/acct.S, \
	libc/arch-x86/syscalls/read.S, \
	libc/arch-x86/syscalls/write.S, \
	libc/arch-x86/syscalls/pread64.S, \
	libc/arch-x86/syscalls/pwrite64.S, \
	libc/arch-x86/syscalls/__open.S, \
	libc/arch-x86/syscalls/__openat.S, \
	libc/arch-x86/syscalls/close.S, \
	libc/arch-x86/syscalls/lseek.S, \
	libc/arch-x86/syscalls/__llseek.S, \
	libc/arch-x86/syscalls/getpid.S, \
	libc/arch-x86/syscalls/__mmap2.S, \
	libc/arch-x86/syscalls/munmap.S, \
	libc/arch-x86/syscalls/mremap.S, \
	libc/arch-x86/syscalls/msync.S, \
	libc/arch-x86/syscalls/mprotect.S, \
	libc/arch-x86/syscalls/madvise.S, \
	libc/arch-x86/syscalls/mlock.S, \
	libc/arch-x86/syscalls/munlock.S, \
	libc/arch-x86/syscalls/mlockall.S, \
	libc/arch-x86/syscalls/munlockall.S, \
	libc/arch-x86/syscalls/mincore.S, \
	libc/arch-x86/syscalls/__ioctl.S, \
	libc/arch-x86/syscalls/readv.S, \
	libc/arch-x86/syscalls/writev.S, \
	libc/arch-x86/syscalls/__fcntl.S, \
	libc/arch-x86/syscalls/flock.S, \
	libc/arch-x86/syscalls/fchmod.S, \
	libc/arch-x86/syscalls/dup.S, \
	libc/arch-x86/syscalls/pipe.S, \
	libc/arch-x86/syscalls/pipe2.S, \
	libc/arch-x86/syscalls/dup2.S, \
	libc/arch-x86/syscalls/select.S, \
	libc/arch-x86/syscalls/ftruncate.S, \
	libc/arch-x86/syscalls/ftruncate64.S, \
	libc/arch-x86/syscalls/getdents.S, \
	libc/arch-x86/syscalls/fsync.S, \
	libc/arch-x86/syscalls/fdatasync.S, \
	libc/arch-x86/syscalls/fchown.S, \
	libc/arch-x86/syscalls/sync.S, \
	libc/arch-x86/syscalls/__fcntl64.S, \
	libc/arch-x86/syscalls/__fstatfs64.S, \
	libc/arch-x86/syscalls/sendfile.S, \
	libc/arch-x86/syscalls/fstatat.S, \
	libc/arch-x86/syscalls/mkdirat.S, \
	libc/arch-x86/syscalls/fchownat.S, \
	libc/arch-x86/syscalls/fchmodat.S, \
	libc/arch-x86/syscalls/renameat.S, \
	libc/arch-x86/syscalls/fsetxattr.S, \
	libc/arch-x86/syscalls/fgetxattr.S, \
	libc/arch-x86/syscalls/flistxattr.S, \
	libc/arch-x86/syscalls/fremovexattr.S, \
	libc/arch-x86/syscalls/link.S, \
	libc/arch-x86/syscalls/unlink.S, \
	libc/arch-x86/syscalls/unlinkat.S, \
	libc/arch-x86/syscalls/chdir.S, \
	libc/arch-x86/syscalls/mknod.S, \
	libc/arch-x86/syscalls/chmod.S, \
	libc/arch-x86/syscalls/chown.S, \
	libc/arch-x86/syscalls/lchown.S, \
	libc/arch-x86/syscalls/mount.S, \
	libc/arch-x86/syscalls/umount2.S, \
	libc/arch-x86/syscalls/fstat.S, \
	libc/arch-x86/syscalls/stat.S, \
	libc/arch-x86/syscalls/lstat.S, \
	libc/arch-x86/syscalls/mkdir.S, \
	libc/arch-x86/syscalls/readlink.S, \
	libc/arch-x86/syscalls/rmdir.S, \
	libc/arch-x86/syscalls/rename.S, \
	libc/arch-x86/syscalls/__getcwd.S, \
	libc/arch-x86/syscalls/access.S, \
	libc/arch-x86/syscalls/faccessat.S, \
	libc/arch-x86/syscalls/symlink.S, \
	libc/arch-x86/syscalls/fchdir.S, \
	libc/arch-x86/syscalls/truncate.S, \
	libc/arch-x86/syscalls/setxattr.S, \
	libc/arch-x86/syscalls/lsetxattr.S, \
	libc/arch-x86/syscalls/getxattr.S, \
	libc/arch-x86/syscalls/lgetxattr.S, \
	libc/arch-x86/syscalls/listxattr.S, \
	libc/arch-x86/syscalls/llistxattr.S, \
	libc/arch-x86/syscalls/removexattr.S, \
	libc/arch-x86/syscalls/lremovexattr.S, \
	libc/arch-x86/syscalls/__statfs64.S, \
	libc/arch-x86/syscalls/unshare.S, \
	libc/arch-x86/syscalls/pause.S, \
	libc/arch-x86/syscalls/gettimeofday.S, \
	libc/arch-x86/syscalls/settimeofday.S, \
	libc/arch-x86/syscalls/times.S, \
	libc/arch-x86/syscalls/nanosleep.S, \
	libc/arch-x86/syscalls/clock_gettime.S, \
	libc/arch-x86/syscalls/clock_settime.S, \
	libc/arch-x86/syscalls/clock_getres.S, \
	libc/arch-x86/syscalls/clock_nanosleep.S, \
	libc/arch-x86/syscalls/getitimer.S, \
	libc/arch-x86/syscalls/setitimer.S, \
	libc/arch-x86/syscalls/__timer_create.S, \
	libc/arch-x86/syscalls/__timer_settime.S, \
	libc/arch-x86/syscalls/__timer_gettime.S, \
	libc/arch-x86/syscalls/__timer_getoverrun.S, \
	libc/arch-x86/syscalls/__timer_delete.S, \
	libc/arch-x86/syscalls/utimes.S, \
	libc/arch-x86/syscalls/utimensat.S, \
	libc/arch-x86/syscalls/sigaction.S, \
	libc/arch-x86/syscalls/sigprocmask.S, \
	libc/arch-x86/syscalls/__sigsuspend.S, \
	libc/arch-x86/syscalls/__rt_sigaction.S, \
	libc/arch-x86/syscalls/__rt_sigprocmask.S, \
	libc/arch-x86/syscalls/__rt_sigtimedwait.S, \
	libc/arch-x86/syscalls/sigpending.S, \
	libc/arch-x86/syscalls/signalfd4.S, \
	libc/arch-x86/syscalls/socket.S, \
	libc/arch-x86/syscalls/bind.S, \
	libc/arch-x86/syscalls/connect.S, \
	libc/arch-x86/syscalls/listen.S, \
	libc/arch-x86/syscalls/accept.S, \
	libc/arch-x86/syscalls/getsockname.S, \
	libc/arch-x86/syscalls/getpeername.S, \
	libc/arch-x86/syscalls/socketpair.S, \
	libc/arch-x86/syscalls/sendto.S, \
	libc/arch-x86/syscalls/recvfrom.S, \
	libc/arch-x86/syscalls/shutdown.S, \
	libc/arch-x86/syscalls/setsockopt.S, \
	libc/arch-x86/syscalls/getsockopt.S, \
	libc/arch-x86/syscalls/sendmsg.S, \
	libc/arch-x86/syscalls/recvmsg.S, \
	libc/arch-x86/syscalls/sched_setscheduler.S, \
	libc/arch-x86/syscalls/sched_getscheduler.S, \
	libc/arch-x86/syscalls/sched_yield.S, \
	libc/arch-x86/syscalls/sched_setparam.S, \
	libc/arch-x86/syscalls/sched_getparam.S, \
	libc/arch-x86/syscalls/sched_get_priority_max.S, \
	libc/arch-x86/syscalls/sched_get_priority_min.S, \
	libc/arch-x86/syscalls/sched_rr_get_interval.S, \
	libc/arch-x86/syscalls/sched_setaffinity.S, \
	libc/arch-x86/syscalls/__sched_getaffinity.S, \
	libc/arch-x86/syscalls/__getcpu.S, \
	libc/arch-x86/syscalls/ioprio_set.S, \
	libc/arch-x86/syscalls/ioprio_get.S, \
	libc/arch-x86/syscalls/uname.S, \
	libc/arch-x86/syscalls/umask.S, \
	libc/arch-x86/syscalls/__reboot.S, \
	libc/arch-x86/syscalls/__syslog.S, \
	libc/arch-x86/syscalls/init_module.S, \
	libc/arch-x86/syscalls/delete_module.S, \
	libc/arch-x86/syscalls/klogctl.S, \
	libc/arch-x86/syscalls/sysinfo.S, \
	libc/arch-x86/syscalls/personality.S, \
	libc/arch-x86/syscalls/perf_event_open.S, \
	libc/arch-x86/syscalls/futex.S, \
	libc/arch-x86/syscalls/epoll_create.S, \
	libc/arch-x86/syscalls/epoll_ctl.S, \
	libc/arch-x86/syscalls/epoll_wait.S, \
	libc/arch-x86/syscalls/inotify_init.S, \
	libc/arch-x86/syscalls/inotify_add_watch.S, \
	libc/arch-x86/syscalls/inotify_rm_watch.S, \
	libc/arch-x86/syscalls/poll.S, \
	libc/arch-x86/syscalls/eventfd.S

build_xb_libc_common_src =  \
	${build_xb_syscall_src}, \
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
	libc/arch-x86/bionic/clone.S, \
	libc/arch-x86/bionic/_exit_with_stack_teardown.S, \
	libc/arch-x86/bionic/futex_x86.S, \
	libc/arch-x86/bionic/__get_sp.S, \
	libc/arch-x86/bionic/__get_tls.c, \
	libc/arch-x86/bionic/_setjmp.S, \
	libc/arch-x86/bionic/setjmp.S, \
	libc/arch-x86/bionic/__set_tls.c, \
	libc/arch-x86/bionic/sigsetjmp.S, \
	libc/arch-x86/bionic/syscall.S, \
	libc/arch-x86/bionic/vfork.S, \
	libc/arch-x86/string/bcopy_wrapper.S, \
	libc/arch-x86/string/bzero_wrapper.S, \
	libc/arch-x86/string/ffs.S, \
	libc/arch-x86/string/memcmp_wrapper.S, \
	libc/arch-x86/string/memcpy_wrapper.S, \
	libc/arch-x86/string/memmove_wrapper.S, \
	libc/arch-x86/string/memset_wrapper.S, \
	libc/arch-x86/string/strcmp_wrapper.S, \
	libc/arch-x86/string/strlen_wrapper.S, \
	libc/arch-x86/string/strncmp_wrapper.S

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
# libdl.so
####
build_xb_libdl_bin        = libdl.so
build_xb_libdl_cflags     = ${build_xb_libc_cmn_cflags}
build_xb_libdl_ldflags    = ${build_xb_libc_cmn_ldflags} -Wl,--exclude-libs=libgcc.a -Wl,--exclude-libs=libgcc_eh.a
build_xb_libdl_src_in     = libdl/libdl.c
build_xb_libdl_src_ex     = 
build_xb_libdl_src_mk     = libdl/libdl.c

####
# CRT (libc run-time)
####
build_xb_libc_crt_bin     =
build_xb_libc_crt_cflags  = -DUSE_SSE2=1 -DUSE_SSE3=1 -DPLATFORM_SDK_VERSION=18 \
	-I${basedir}/xbionic/libc/include \
    -I${basedir}/xbionic/libc/private \
    -I${basedir}/xbionic/libc/arch-${build_cfg_arch}/include
build_xb_libc_crt_ldflags = 
build_xb_libc_crt_src_in  = libc/bionic/crtbrand.c, libc/arch-common/bionic/crt*.S, libc/arch-common/bionic/crt*.c
build_xb_libc_crt_src_ex  = 
build_xb_libc_crt_src_mk  = ${build_xb_libc_crt_src_in}

####
# libbionic_ssp.a
####
build_xb_libc_ssp_bin     = libbionic_ssp.a
build_xb_libc_ssp_cflags  = ${build_xb_libc_cmn_cflags} -fno-stack-protector -Werror -I${basedir}/xbionic/libc
build_xb_libc_ssp_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_ssp_src_in  = libc/bionic/__stack_chk_fail.cpp
build_xb_libc_ssp_src_ex  = 
build_xb_libc_ssp_src_mk  = ${build_xb_libc_ssp_src_in}

####
# libc_freebsd.a
####
build_xb_libc_ufb_bin     = libc_freebsd.a
build_xb_libc_ufb_cflags  = ${build_xb_libc_cmn_cflags} \
	-I${basedir}/xbionic/libc \
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
	-I${basedir}/xbionic/libc \
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
	-I${basedir}/xbionic/libc/upstream-netbsd/libc/include \
	-I${basedir}/xbionic/libm/include
build_xb_libc_com_ldflags = ${build_xb_libc_cmn_ldflags}
build_xb_libc_com_src_in  = ${build_xb_libc_r_common_src}
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
build_xb_libc_lcs_bin     = libc.so
build_xb_libc_lcs_cflags  = ${build_xb_libc_cmn_cflags} -DPTHREAD_DEBUG -DPTHREAD_DEBUG_ENABLED=0 ${build_xb_libc_cmn_incs} -fno-stack-protector
build_xb_libc_lcs_ldflags = ${build_xb_libc_cmn_ldflags} \
		/home/appos/gitrepo/android-x86/prebuilts/gcc/linux-x86/x86/i686-linux-android-4.7/lib/gcc/i686-linux-android/4.7/libgcc.a
build_xb_libc_lcs_src_in  = ${build_xb_libc_arch_dynamic_src}, ${build_xb_libc_s_common_src}, \
		libc/bionic/dlmalloc.c, \
		libc/bionic/malloc_debug_common.cpp, \
		libc/bionic/pthread_debug.cpp, \
		libc/bionic/libc_init_dynamic.cpp
build_xb_libc_lcs_src_ex  = 
build_xb_libc_lcs_src_mk  = ${build_xb_libc_lcs_src_in}

####
# libc_malloc_debug_qemu.so
####
build_xb_libc_src_mdqbin = libc_malloc_debug_qemu.so
build_xb_libc_src_mdq_cf = ${build_xb_libc_cmn_cflags} -DMALLOC_QEMU_INSTRUMENT
build_xb_libc_src_mdq_lf = ${build_xb_libc_cmn_ldflags} -lc -ldl
build_xb_libc_src_mdq_in = libc/bionic/malloc_debug_qemu.cpp
build_xb_libc_src_mdq_ex = 
build_xb_libc_src_mdq_mk = $(wildcard $(basedir)/xbionic/libc/unistd/*.S)
build_xb_libc_src_mdq_mk += $(wildcard $(basedir)/src/base/src/posix/*.c)


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

