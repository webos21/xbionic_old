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

#include <unistd.h>

#include "___fd_win.h"

// read from a file descriptor
// ref {
//     http://linux.die.net/man/2/read
// }
ssize_t read(int fd, void *buf, size_t count) {
	NTSTATUS ret = 0;
	ssize_t rbytes = 0;
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

	if (fdesc->fdtype == XB_FD_TYPE_FILE || fdesc->fdtype == XB_FD_TYPE_PIPE) {
		IO_STATUS_BLOCK iosb;

		ntsc_t *ntfp = ntdll_getFP();

		ret = ntfp->FP_NtReadFile(fdesc->desc.f.fd, NULL, NULL, NULL, &iosb, buf, (ULONG) count, NULL, NULL);
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
		} else {
			rbytes = iosb.Information;
		}
	} else if (fdesc->fdtype == XB_FD_TYPE_SOCK) {
		ntsock_t *wsfp = ntsock_getFP();
		rbytes = wsfp->FP_recv(fdesc->desc.s.fd, (char*)buf, (int) count, 0);
		if (rbytes == SOCKET_ERROR) {
			int err = wsfp->FP_WSAGetLastError();
			switch (err) {
			case WSAEWOULDBLOCK:
				errno = EWOULDBLOCK;
				return -1;
			case WSAEBADF:
				errno = EBADF;
				return -1;
			case WSAECONNREFUSED:
				errno = ECONNREFUSED;
				return -1;
			case WSAEFAULT:
				errno = EFAULT;
				return -1;
			case WSAEINTR:
				errno = EINTR;
				return -1;
			case WSAENOTCONN:
				errno = ENOTCONN;
				return -1;
			case WSAENOTSOCK:
				errno = ENOTSOCK;
				return -1;
			default:
				errno = EINVAL;
				return -1;
			}
		}
	}

	return rbytes;
}
