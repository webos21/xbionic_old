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
//     http://linux.die.net/man/2/llseek
//     http://msdn.microsoft.com/en-us/library/windows/desktop/ms684283(v=vs.85).aspx
// }
int __llseek(int fd, unsigned long offset_hi, unsigned long offset_lo, loff_t *result, int whence) {
	xb_fd_t *fdesc = NULL;

	if (result == NULL) {
		errno = EINVAL;
		return -1;
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
		NTSTATUS ret;
		IO_STATUS_BLOCK iosb;
		FILE_POSITION_INFORMATION  posInfo;

		ntsc_t *ntfp = ntdll_getFP();

		switch (whence) {
		case SEEK_SET:
			{
				posInfo.CurrentByteOffset.HighPart = offset_hi;
				posInfo.CurrentByteOffset.LowPart = offset_lo;
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
				(*result) = posInfo.CurrentByteOffset.QuadPart;
				return 0;
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
				if (offset_hi == 0 && offset_lo == 0) {
					// Get Current Position : SEEK_CUR and offset == 0
					errno = 0;
					(*result) = posInfo.CurrentByteOffset.QuadPart;
					return 0;
				}
				posInfo.CurrentByteOffset.HighPart += offset_hi;
				posInfo.CurrentByteOffset.LowPart += offset_lo;
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
				(*result) = posInfo.CurrentByteOffset.QuadPart;
				return 0;
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
				if (offset_hi == 0 && offset_lo == 0) {
					// Get End Position : SEEK_END and offset == 0
					errno = 0;
					(*result) = stdInfo.EndOfFile.QuadPart;
					return 0;
				}
				posInfo.CurrentByteOffset.HighPart = stdInfo.EndOfFile.HighPart + offset_hi;
				posInfo.CurrentByteOffset.LowPart = stdInfo.EndOfFile.LowPart + offset_lo;
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
				(*result) = posInfo.CurrentByteOffset.QuadPart;
				return 0;
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
