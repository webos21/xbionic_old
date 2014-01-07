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

// create a child process
// (same as bionic/clone.c, but it is not used!!!)
// (see the bionic/clone.c : __pthread_clone / __bionic_clone)
// ref {
//     http://linux.die.net/man/2/clone
// }
int __sys_clone(void* (*fn)(void*), void* tls, int flags, void* arg) {
	errno = 0;
	return 0;
}
