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

#include <ntsock.h>

#include <errno.h>
#include <sys/select.h>

#include "___fd_win.h"

// initiate a connection on a socket  
// ref {
//     http://linux.die.net/man/2/select
// }
int select(int n, fd_set *readfds, fd_set *writefds, fd_set *errfds, struct timeval *timeout) {
	int ret;
	xb_fd_t *fdesc = NULL;

	ntsock_t *wsfp = ntsock_getFP();

	// FIXME!!!
	// type converting needed!!
	WSA_fd_set rfds;
	WSA_fd_set wfds;
	WSA_fd_set efds;

	ret = wsfp->FP_select(n, &rfds, &wfds, &efds, timeout);
	if (ret == SOCKET_ERROR) {
		int err = wsfp->FP_WSAGetLastError();
		switch (err) {
		case WSANOTINITIALISED:
		case WSAENETDOWN:
			errno = EACCES;
			return -1;
		case WSAEADDRINUSE:
			errno = EADDRINUSE;
			return -1;
		case WSAEINTR:
			errno = EINTR;
			return -1;
		case WSAEINPROGRESS:
			errno = EINPROGRESS;
			return -1;
		case WSAEALREADY:
			errno = EALREADY;
			return -1;
		case WSAEADDRNOTAVAIL:
			errno = EADDRNOTAVAIL;
			return -1;
		case WSAEAFNOSUPPORT:
			errno = EAFNOSUPPORT;
			return -1;
		case WSAECONNREFUSED:
			errno = ECONNREFUSED;
			return -1;
		case WSAEFAULT:
			errno = EFAULT;
			return -1;
		case WSAEISCONN:
			errno = EISCONN;
			return -1;
		case WSAENETUNREACH:
			errno = ENETUNREACH;
			return -1;
		case WSAEHOSTUNREACH:
			errno = EHOSTUNREACH;
			return -1;
		case WSAENOBUFS:
			errno = ENOBUFS;
			return -1;
		case WSAENOTSOCK:
			errno = ENOTSOCK;
			return -1;
		case WSAETIMEDOUT:
			errno = ETIMEDOUT;
			return -1;
		case WSAEWOULDBLOCK:
			errno = EWOULDBLOCK;
			return -1;
		case WSAEACCES:
			errno = EACCES;
			return -1;
		case WSAEINVAL:
		default:
			errno = EINVAL;
			return -1;
		}
	}

	errno = 0;
	return 0;
}
