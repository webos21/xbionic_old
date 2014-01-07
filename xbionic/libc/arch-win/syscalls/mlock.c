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
#include <sys/mman.h>

// lock part of the calling process's virtual address space into RAM
//  - according to the result of web searching,
//    locking of virtual memory is problematic.
//  => watch out to use it!!!
// ref {
//     http://linux.die.net/man/2/mlock
// }
int mlock(const void *addr, size_t len) {
	NTSTATUS st;
	ULONG reqSize = len;
	ntsc_t *ntfp = ntdll_getFP();

	st = ntfp->FP_NtLockVirtualMemory(XbNtCurrentProcess(), (PVOID *)&addr, &reqSize, VM_LOCK_1);
	if (!NT_SUCCESS(st)) {
		switch(st) {
		case STATUS_ACCESS_DENIED:
			errno = EPERM;
			return -1;
		case STATUS_WORKING_SET_QUOTA:
		case STATUS_INSUFFICIENT_RESOURCES:
			errno = ENOMEM;
			return -1;
		case STATUS_INVALID_HANDLE:
		case STATUS_INVALID_PARAMETER_2:
		default:
			errno = EINVAL;
			return -1;
		}
	}
	errno = 0;
	return 0;
}
