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

// synchronize a file with a memory map
// ref {
//     http://linux.die.net/man/2/msync
// }
int msync(const void *addr, size_t length, int flags) {
	SIZE_T flushLen;
	NTSTATUS st;
	IO_STATUS_BLOCK iosb;

	ntsc_t *ntfp = ntdll_getFP();

	if ((flags & MS_ASYNC) && (flags & MS_SYNC)) {
		errno = EINVAL;
		return -1;
	}

	// Save amount of bytes to flush to a local var
	flushLen = length;

	/* Flush the view */
	st = ntfp->FP_NtFlushVirtualMemory(XbNtCurrentProcess(), &addr, &flushLen, &iosb);
	if (!NT_SUCCESS(st)) {
		switch(st) {
		case STATUS_NOT_MAPPED_DATA:
			errno = ENOMEM;
			return -1;
		case STATUS_FILE_LOCK_CONFLICT:
			errno = EBUSY;
			return -1;
		case STATUS_ACCESS_DENIED:
		default:
			errno = EINVAL;
			return -1;
		}
	}
	errno = 0;
	return 0;
}
