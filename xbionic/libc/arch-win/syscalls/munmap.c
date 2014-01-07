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

// unmap files or devices into memory
// ref {
//     http://linux.die.net/man/2/munmap
// }
int munmap(void *addr, size_t length) {
	NTSTATUS st;

	ntsc_t *ntfp = ntdll_getFP();

	// Unmap the section
	st = ntfp->FP_NtUnmapViewOfSection(XbNtCurrentProcess(), addr);
	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_INVALID_PAGE_PROTECTION:
			// Flush the region if it was a "secure memory cache"
			if (ntfp->FP_RtlFlushSecureMemoryCache(addr, length)) {
				// Now try to unmap again
				st = ntfp->FP_NtUnmapViewOfSection(XbNtCurrentProcess(), addr);
				if (NT_SUCCESS(st)) {
					errno = 0;
					return 0;
				}
			}
		case STATUS_INVALID_ADDRESS:
		default:
			errno = EINVAL;
			return -1;
		}
	}

	// Otherwise, return success
	errno = 0;
	return 0;
}
