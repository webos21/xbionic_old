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
#include <ntsock.h>

#include <errno.h>
#include <sys/types.h>

#include "___fd_win.h"

// duplicate a file descriptor
// ref {
//     http://linux.die.net/man/2/dup
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff566445(v=vs.85).aspx
// }
int dup(int oldfd) {
	xb_fd_t ndesc;
	xb_fd_t *fdesc = NULL;

	ULONG options = DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES;

	ntsc_t *ntfp = ntdll_getFP();

	fdesc = xb_fd_get(oldfd);
	if (fdesc == NULL) {
		errno = EBADF;
		return -1;
	} else {
		NTSTATUS ret;

		ntfp->FP_RtlCopyMemory(&ndesc, fdesc, sizeof(ndesc));
		ndesc.desc.f.fd = NULL;
		ret = ntfp->FP_NtDuplicateObject(XbNtCurrentProcess(), fdesc->desc.f.fd, 
			XbNtCurrentProcess(), &ndesc.desc.f.fd, 
			0, 0, options);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_INVALID_PARAMETER:
			case STATUS_ACCESS_VIOLATION:
			default:
				errno = EINVAL;
				return -1;
			}
		}
		return xb_fd_open(&ndesc);
	}
}
