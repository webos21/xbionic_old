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

#include <unistd.h>

#include "___fd_win.h"

// reposition read/write file offset
// ref {
//     http://linux.die.net/man/2/lseek
//     http://msdn.microsoft.com/en-us/library/windows/desktop/ms684283(v=vs.85).aspx
// }
off_t lseek(int fd, off_t offset, int whence) {
	xb_fd_t *fdesc = NULL;

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
		NTSTATUS ret;
		IO_STATUS_BLOCK iosb;
		FILE_POSITION_INFORMATION  posInfo;

		ntsc_t *ntfp = ntdll_getFP();

		switch (whence) {
		case SEEK_SET:
			{
				posInfo.CurrentByteOffset.QuadPart = offset;
				ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &posInfo, sizeof(posInfo), FilePositionInformation);
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
				errno = 0;
				return offset;
			}
		case SEEK_CUR:
			{
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
				if (offset == 0) {
					// Get Current Position : SEEK_CUR and offset == 0
					errno = 0;
					return (off_t) posInfo.CurrentByteOffset.QuadPart;
				}
				posInfo.CurrentByteOffset.QuadPart += offset;
				ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &posInfo, sizeof(posInfo), FilePositionInformation);
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
				errno = 0;
				return (off_t) posInfo.CurrentByteOffset.QuadPart;
			}
		case SEEK_END:
			{
				FILE_STANDARD_INFORMATION stdInfo;
				ret = ntfp->FP_NtQueryInformationFile(fdesc->desc.f.fd, &iosb, &stdInfo, sizeof(stdInfo), FileStandardInformation);
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
				if (offset == 0) {
					// Get End Position : SEEK_END and offset == 0
					errno = 0;
					return (off_t) stdInfo.EndOfFile.QuadPart;
				}
				posInfo.CurrentByteOffset.QuadPart = stdInfo.EndOfFile.QuadPart;
				posInfo.CurrentByteOffset.QuadPart += offset;
				ret = ntfp->FP_NtSetInformationFile(fdesc->desc.f.fd, &iosb, &posInfo, sizeof(posInfo), FilePositionInformation);
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
				errno = 0;
				return (off_t) posInfo.CurrentByteOffset.QuadPart;
			}
		default:
			errno = EINVAL;
			return -1;
		}
	} else {
		errno = ESPIPE;
		return -1;
	}
}
