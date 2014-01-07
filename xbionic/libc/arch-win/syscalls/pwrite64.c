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

#include "___fd_win.h"

// write to a file descriptor at a given offset
// ref {
//     http://linux.die.net/man/2/pwrite64
// }
ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
	NTSTATUS ret = 0;
	ssize_t wbytes = 0;
	xb_fd_t *fdesc = NULL;

	if (count == 0) {
		errno = 0;
		return 0;
	}

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL) {
		errno = EBADF;
		return -1;
	}
	if (fdesc->fdtype == XB_FD_TYPE_DIR) {
		errno = EISDIR;
		return -1;
	}

	if (fdesc->fdtype == XB_FD_TYPE_FILE) {
		IO_STATUS_BLOCK iosb;
		LARGE_INTEGER pos;
		FILE_POSITION_INFORMATION  posInfo;

		ntsc_t *ntfp = ntdll_getFP();

		// Get the file position
		ret = ntfp->FP_NtQueryInformationFile(fdesc->desc.f.fd, &iosb, &posInfo, sizeof(posInfo), FilePositionInformation);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_PENDING:
				errno = EWOULDBLOCK;
				return -1;
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		}

		pos.QuadPart = offset;

		ret = ntfp->FP_NtWriteFile(fdesc->desc.f.fd, NULL, NULL, NULL, &iosb, (PVOID)buf, (ULONG) count, &pos, NULL);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_PENDING:
				errno = EWOULDBLOCK;
				return -1;
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		} 

		// set the result
		errno = 0;
		wbytes = iosb.Information;

		// Restore the file position
		ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &posInfo, sizeof(posInfo), FilePositionInformation);
	} else {
		errno = ESPIPE;
		return -1;
	}

	return wbytes;
}
