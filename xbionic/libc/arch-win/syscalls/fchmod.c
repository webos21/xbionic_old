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
#include <sys/stat.h> 

#include "___fd_win.h"

// change permissions of a file 
// ref {
//     http://linux.die.net/man/2/fchmod
//     http://msdn.microsoft.com/en-us/library/1z319a54.aspx
// }
int fchmod(int fd, mode_t mode) {
	xb_fd_t *fdesc = NULL;

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL || (fdesc->fdtype != XB_FD_TYPE_FILE && fdesc->fdtype != XB_FD_TYPE_DIR)) {
		errno = EBADF;
		return -1;
	} else {
// Nothing special!!!
/*
		NTSTATUS ret = 0;
		ULONG oldAttr = 0;
		ULONG newAttr = 0;

		IO_STATUS_BLOCK iosb;
		FILE_ATTRIBUTE_TAG_INFORMATION fati;

		ntsc_t *ntfp = ntdll_getFP();
		ret = ntfp->FP_NtQueryInformationFile(fdesc->desc.f.fd, &iosb, &fati, sizeof(fati), FileAttributeTagInformation);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_END_OF_FILE:
				errno = 0;
				return 0;
			case STATUS_PENDING:
				errno = EWOULDBLOCK;
				return -1;
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		}

		oldAttr = fbi.FileAttributes;

		ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &fati, sizeof(fati), FileAttributeTagInformation);
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
//*/
	}

	errno = 0;
	return 0;
}
