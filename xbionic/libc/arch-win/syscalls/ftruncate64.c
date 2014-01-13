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

// truncate a file to a specified length  
// ref {
//     http://linux.die.net/man/2/ftruncate64
// }
int ftruncate64(int fd, off64_t length) {
	xb_fd_t *fdesc = NULL;

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL || (fdesc->fdtype != XB_FD_TYPE_FILE && fdesc->fdtype != XB_FD_TYPE_DIR)) {
		errno = EBADF;
		return -1;
	}

	if (fdesc->fdtype == XB_FD_TYPE_DIR) {
		errno = EISDIR;
		return -1;
	} else {
		NTSTATUS ret = 0;

		IO_STATUS_BLOCK                 iosb;
		FILE_END_OF_FILE_INFORMATION	eofInfo;
		FILE_ALLOCATION_INFORMATION		fallocInfo;

		ntsc_t *ntfp = ntdll_getFP();

		eofInfo.EndOfFile.QuadPart = length;
		fallocInfo.AllocationSize.QuadPart = length;

		ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &eofInfo, sizeof(eofInfo), FileEndOfFileInformation);
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
		ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &fallocInfo, sizeof(fallocInfo), FileAllocationInformation);
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
	}

	errno = 0;
	return 0;
}
