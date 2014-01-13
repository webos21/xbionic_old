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

#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#include "___fd_win.h"

// manipulate file descriptor
// ref {
//     http://linux.die.net/man/2/fcntl
// }
int __fcntl64(int fd, int cmd, void *args) {
	xb_fd_t *fdesc = NULL;
	int intArg;

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL) {
		errno = EBADF;
		return -1;
	} else {
		switch (cmd) {
		case F_DUPFD:
			return dup2(fd, fdesc->desc.f.flag & ~O_CLOEXEC);
		case F_GETFL:
			errno = 0;
			return fdesc->desc.f.flag;
		case F_SETFL:
			intArg = (int) args;
			fdesc->desc.f.flag = intArg;
			errno = 0;
			return 0;
		case F_GETFD:
			errno = 0;
			return (fdesc->desc.f.flag & O_CLOEXEC) ? FD_CLOEXEC : 0;
		case F_SETFD:
			intArg = (int) args;
			if (intArg == FD_CLOEXEC) {
				fdesc->desc.f.flag |= O_CLOEXEC;
			} else {
				fdesc->desc.f.flag &= ~O_CLOEXEC;
			}
			errno = 0;
			return 0;

			// FIXME
			// FIXME
			// FIXME
		case F_GETLK:
		case F_GETLK64:
			if (args == NULL) {
				errno = EFAULT;
				return -1;
			} else {
				struct flock *lckOp = (struct flock *) args;

				return 0;
			}
		case F_SETLK:
		case F_SETLK64:
			if (args == NULL) {
				errno = EFAULT;
				return -1;
			} else {
				struct flock *lckOp = (struct flock *) args;
				return 0;
			}
		case F_SETLKW:
		case F_SETLKW64:
			if (args == NULL) {
				errno = EFAULT;
				return -1;
			} else {
				struct flock *lckOp = (struct flock *) args;
				return 0;
			}

			// FIXME
			// FIXME
			// FIXME
		case F_GETSIG:
		case F_SETSIG:
		case F_GETOWN:
		case F_SETOWN:
		case F_GETOWN_EX:
		case F_SETOWN_EX:
		case F_SETLEASE:
		case F_GETLEASE:
		case F_NOTIFY:
			errno = 0;
			return 0;
		default:
			errno = EINVAL;
			return -1;
		}
	}
}
