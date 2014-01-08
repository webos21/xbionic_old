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
#include <unistd.h>

#include "___fd_win.h"

// duplicate a file descriptor
// ref {
//     http://linux.die.net/man/2/dup2
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff566445(v=vs.85).aspx
// }
int dup2(int oldfd, int newfd) {
	xb_fd_t newDesc;
	xb_fd_t *odesc = NULL;
	xb_fd_t *ndesc = NULL;

	ULONG options = DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES;

	ntsc_t *ntfp = ntdll_getFP();

	if (oldfd == newfd) {
		errno = EINVAL;
		return -1;
	}

	odesc = xb_fd_get(oldfd);
	if (odesc == NULL) {
		errno = EBADF;
		return -1;
	} else {
		NTSTATUS ret;

		ndesc = xb_fd_get(newfd);
		if (ndesc != NULL) {
			if ((odesc->fdtype == ndesc->fdtype) &&
				(odesc->fdtype == XB_FD_TYPE_FILE && strcmp(odesc->desc.f.path, ndesc->desc.f.path) == 0)) {
				// same handle
				errno = 0;
				return newfd;
			} else {
				close(newfd);
			}
		}

		ntfp->FP_RtlCopyMemory(&newDesc, odesc, sizeof(newDesc));
		newDesc.desc.f.fd = NULL;
		ret = ntfp->FP_NtDuplicateObject(XbNtCurrentProcess(), odesc->desc.f.fd, 
			XbNtCurrentProcess(), &newDesc.desc.f.fd, 
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
		return xb_fd_open_idx(&newDesc, newfd);
	}
}
