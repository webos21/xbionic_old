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

#include <sys/wait.h>

// wait for child process to change state
// ref {
//     http://www.lehman.cuny.edu/cgi-bin/man-cgi?waitid+2
// }
int __waitid(idtype_t which, id_t id, siginfo_t* info, int options, struct rusage* ru) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("syscall is called, but it is not implemented!!!\n");

	switch (which) {
	case P_PID:
	case P_PGID:
	case P_ALL:
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	// [options] is a bitwise value!!
	errno = 0;
	return 0;
}
