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

#include <sys/time.h>
#include <sys/resource.h> 

// get program scheduling priority 
// (if who is 0, get the priority of caller)
// ref {
//     http://linux.die.net/man/2/setpriority
//     http://msdn.microsoft.com/en-us/library/windows/desktop/ms685100(v=vs.85).aspx
// }
int __getpriority(int which, int who) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("__getpriority() is called, but it is not implemented!!!\n");

	switch (which) {
	case PRIO_PROCESS:
		break;
	case PRIO_PGRP:
		break;
	case PRIO_USER:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	// FIXME : Just return 0
	errno = 0;
	return 0;
}
