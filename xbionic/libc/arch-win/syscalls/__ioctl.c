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
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/if.h>

#include "___fd_win.h"

// control device
// ref {
//     http://linux.die.net/man/2/ioctl
// }
int __ioctl(int fd, int req, void *args) {
	xb_fd_t *fdesc = NULL;
	int intArg;

	fdesc = xb_fd_get(fd);
	if (fdesc == NULL) {
		errno = EBADF;
		return -1;
	} else {
		// FIXME
		// FIXME
		// FIXME
		switch (req) {
		case SIOCGIFNAME:   // Socket I/O : Get Interface by Name
			if (args != NULL) {
				struct ifreq *ifr = (struct ifreq *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case SIOCGIFINDEX:  // Socket I/O : Get Interface by Index
			if (args != NULL) {
				struct ifreq *ifr = (struct ifreq *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCGETS:       // Terminal I/O : Get Attributes
			if (args != NULL) {
				struct termios *tio = (struct termios *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCSETS:       // Terminal I/O : Set Attributes
			if (args != NULL) {
				struct termios *tio = (struct termios *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCXONC:       // Terminal I/O : Control Flow
			if (args != NULL) {
				int action = (int) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCFLSH:       // Terminal I/O : Flush
			if (args != NULL) {
				int que = (int) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCSBRK:       // Terminal I/O : Drain
			if (args != NULL) {
				int que = (int) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TCSBRKP:      // Terminal I/O : Send Break
			if (args != NULL) {
				int duration = (int) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TIOCGSID:     // Terminal I/O : Get SID
			if (args != NULL) {
				pid_t *pid = (pid_t *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TIOCGPTN:    // Terminal I/O : Get PTN
			if (args != NULL) {
				unsigned int *ptn = (unsigned int *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TIOCGPGRP:   // Terminal I/O : Get PGRP
			if (args != NULL) {
				pid_t *pid = (pid_t *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		case TIOCSPTLCK:  // Terminal I/O : Spin Lock/Unlock
			if (args != NULL) {
				int *lock = (int *) args;
			} else {
				errno = EINVAL;
				return -1;
			}
		default:
			errno = EINVAL;
			return -1;
		}
	}
}
