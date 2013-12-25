/*
 * Copyright 2013 Cheolmin Jo (webos21@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ntdll.h>
#include <errno.h>
#include <sys/types.h>

#include <linux/ptrace.h>

// used to implement breakpoint debugging and system call tracing
// ref {
//   http://linux.die.net/man/2/ptrace
//   http://mikecvet.wordpress.com/2010/08/14/ptrace-tutorial/
//   http://stackoverflow.com/questions/865106/is-there-something-like-linux-ptrace-syscall-in-windows
//   http://stackoverflow.com/questions/864839/monitoring-certain-system-calls-done-by-a-process-in-windows
//   http://msdn.microsoft.com/en-us/library/aa363691%28VS.85%29.aspx
// }
// long __ptrace(int request, pid_t pid, void *addr, void *data);
long __ptrace(int request, pid_t pid, void *addr, void *data) {
	ntsc_t *ntfp = ntdll_getFP();

	switch(request) {
	case PTRACE_PEEKUSR:
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		break;
	default:
		break;
	}

	ntfp->FP_DbgPrint("__ptrace() is called, but it is not implemented!!!\n");
	errno = 0;
	return 0;
}
