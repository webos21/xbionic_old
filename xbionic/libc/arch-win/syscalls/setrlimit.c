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

// set the resource limit
// ref {
//     http://linux.die.net/man/2/setrlimit
// }
int setrlimit(int resource, const struct rlimit *rlim) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("setrlimit() is called, but it is not implemented!!!\n");

	if (rlim == NULL) {
		errno = EFAULT;
		return -1;
	}
	switch(resource) {
	case RLIMIT_AS:
	case RLIMIT_CORE:
	case RLIMIT_CPU:
	case RLIMIT_DATA:
	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_MEMLOCK:
	case RLIMIT_MSGQUEUE:
	case RLIMIT_NICE:
	case RLIMIT_NOFILE:
	case RLIMIT_NPROC:
	case RLIMIT_RSS:
	case RLIMIT_RTPRIO:
	case RLIMIT_RTTIME:
	case RLIMIT_SIGPENDING:
	case RLIMIT_STACK:
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	errno = 0;
	return 0;
}
