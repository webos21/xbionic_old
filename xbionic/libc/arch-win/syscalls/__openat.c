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

#include <sys/stat.h>
#include <fcntl.h>

#include "___fd_win.h"

extern int __open(const char *pathname, int flags, int mode);

// open a file relative to a directory file descriptor
// ref {
//     http://linux.die.net/man/2/openat
// }
int __openat(int dirfd, const char *pathname, int flags, int mode) {
	if (pathname == NULL || pathname[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	if (pathname[0] == '/' || pathname[0] == '\\' ||
		(pathname[1] == ':' && pathname[2] == ':')) {
		// Absolute-Path : just call the __open()
		return __open(pathname, flags, mode);
	} else {
		// calculate the relative path
		char pathBuf[512];
		size_t szLen;
		xb_fd_t *pfd = xb_fd_get(dirfd);
		ntsc_t *ntfp = ntdll_getFP();

		if (pfd == NULL || pfd->fdtype != XB_FD_TYPE_DIR) {
			errno = EBADF;
			return -1;
		}
		ntfp->FP_RtlZeroMemory(pathBuf, sizeof(pathBuf));
		szLen = strlen(pfd->desc.d.path);
		strcpy(pathBuf, pfd->desc.d.path);
		if (pfd->desc.d.path[szLen-1] == '\\' || pfd->desc.d.path[szLen-1] == '/') {
			strcat(pathBuf, pathname);
		} else {
			strcat(pathBuf, "/");
			strcat(pathBuf, pathname);
		}

		return __open(pathBuf, flags, mode);
	}
}
