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

#include <linux/futex.h>
#include <sys/time.h>

// fast user-space locking
// ref {
//     http://man7.org/linux/man-pages/man2/futex.2.html
//     http://locklessinc.com/articles/keyed_events/
// }

#ifdef _MSC_VER

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout) {
	errno = 0;
	return 0;
}

int __futex_wake(volatile void *ftx, int count) {
	errno = 0;
	return 0;
}

int __futex_syscall3(volatile void *ftx, int op, int count) {
	errno = 0;
	return 0;
}

int __futex_syscall4(volatile void *ftx, int op, int val, const struct timespec *timeout) {
	errno = 0;
	return 0;
}

#else  // !_MSC_VER

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout) {
	errno = 0;
	return 0;
}

int __futex_wake(volatile void *ftx, int count) {
	errno = 0;
	return 0;
}

int __futex_syscall3(volatile void *ftx, int op, int count) {
	errno = 0;
	return 0;
}

int __futex_syscall4(volatile void *ftx, int op, int val, const struct timespec *timeout) {
	errno = 0;
	return 0;
}

#endif // _MSC_VER
