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
//#include <ntsock.h>

#include <errno.h>
#include <sys/types.h>

#include "___fd_win.h"

// close a file descriptor
// - NtClose can close a socket!!!
// ref {
//     http://linux.die.net/man/2/close
//     http://msdn.microsoft.com/en-us/library/ms648410(v=vs.85).aspx
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff566417(v=vs.85).aspx
// }
int close(int fd) {
	xb_fd_t *fdesc = NULL;

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL) {
		errno = EBADF;
		return -1;
	} else {
		NTSTATUS ret;
		ntsc_t *ntfp = ntdll_getFP();
		ret = ntfp->FP_NtClose(fdesc->desc.f.fd);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_INVALID_HANDLE:
			default:
				errno = EBADF;
				return -1;
			}
		}
	}

/*
	if (fdesc->fdtype == XB_FD_TYPE_SOCK) {
		int ret;
		ntsock_t *wsfp = ntsock_getFP();
		ret = wsfp->FP_closesocket(fdesc->desc.s.fd);
		if (ret == SOCKET_ERROR) {
			switch (ret) {
			case WSANOTINITIALISED:
			case WSAENETDOWN:
			case WSAEWOULDBLOCK:
				errno = EIO;
				return -1;
			case WSAEINTR:
				errno = EINTR;
				return -1;
			case WSAENOTSOCK:
			default:
				errno = EBADF;
				return -1;
			}
		}
	} else {

	}
*/

	// Success!!
	errno = 0;
	return xb_fd_close(fd);;
}
