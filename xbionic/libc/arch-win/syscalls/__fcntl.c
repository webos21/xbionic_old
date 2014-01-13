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
int __fcntl(int fd, int cmd, void *args) {
	// It is not used in Bionic LibC.
	// __fcntl64 is only used!!!
	errno = 0;
	return 0;
}
