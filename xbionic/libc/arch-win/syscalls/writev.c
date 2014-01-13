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
#include <linux/uio.h>

#include "___fd_win.h"

// write data into multiple buffers 
// ref {
//     http://linux.die.net/man/2/writev
// }
ssize_t writev(int fd, const struct iovec *iov, int iovlen) {
	NTSTATUS ret = 0;
	ssize_t rbytes = 0;
	xb_fd_t *fdesc = NULL;

	ssize_t totalWrite = 0;
	int i = 0;

	if (iov == NULL || iovlen <= 0) {
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
	} else {
		IO_STATUS_BLOCK iosb;

		ntsc_t *ntfp = ntdll_getFP();

		while (i < iovlen) {
			ret = ntfp->FP_NtWriteFile(fdesc->desc.f.fd, NULL, NULL, NULL, &iosb, 
				iov[i].iov_base, (ULONG) iov[i].iov_len,
				NULL, NULL);
			if (!NT_SUCCESS(ret)) {
				break;
			}

			totalWrite += iosb.Information;
			i++;
		}

		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_END_OF_FILE:
				errno = 0;
				break;;
			case STATUS_PENDING:
				errno = EWOULDBLOCK;
				break;
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		}

		return totalWrite;
	}
}
