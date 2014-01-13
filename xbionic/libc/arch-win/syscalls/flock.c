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
#include <sys/file.h>

#include "___fd_win.h"

// apply or remove an advisory lock on an open file  
// ref {
//     http://linux.die.net/man/2/flock
// }
int flock(int fd, int op) {
	NTSTATUS ret = 0;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER byteOffset;
	LARGE_INTEGER byteLength;
	ULONG key = 0;

	xb_fd_t *fdesc = NULL;

	ntsc_t *ntfp = ntdll_getFP();

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL || fdesc->fdtype != XB_FD_TYPE_FILE) {
		errno = EBADF;
		return -1;
	}

	if (((op & LOCK_SH) && (op & LOCK_EX)) || 
		(!(op & LOCK_SH) && !(op & LOCK_EX) && !(op & LOCK_UN))) {
		errno = EINVAL;
		return -1;
	}

	byteOffset.QuadPart = 0;
	byteLength.QuadPart = 0;

	if ((op & LOCK_UN)) {
		ret = ntfp->FP_NtUnlockFile(fdesc->desc.f.fd, &iosb, &byteOffset, &byteLength, key);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_RANGE_NOT_LOCKED:
				break;
			case STATUS_NOT_IMPLEMENTED:   // socket
				errno = EBADF;
				return -1;
			case STATUS_INVALID_PARAMETER: // directory
			default:
				errno = EINVAL;
				return -1;
			}
		}
		errno = 0;
		return 0;
	} else {
		BOOLEAN ex = ((op & LOCK_EX) == LOCK_EX);
		ret = ntfp->FP_NtLockFile(fdesc->desc.f.fd, NULL, NULL, NULL, &iosb, &byteOffset, &byteLength, key, TRUE, ex);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_NOT_IMPLEMENTED:   // socket
				errno = EBADF;
				return -1;
			case STATUS_INVALID_PARAMETER: // directory
			default:
				errno = EINVAL;
				return -1;
			}
		}
		errno = 0;
		return 0;
	}
}
