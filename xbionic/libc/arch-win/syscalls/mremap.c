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

void *__mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

// remap a virtual memory address
//  - no same function, and LINUX specific API.
// ref {
//     http://linux.die.net/man/2/mremap
// }
void *mremap(void *old_address, size_t old_size, size_t new_size, unsigned long flags) {
	void *oldAddr = NULL;

	void *newAddr = old_address;
	SIZE_T newSize = new_size;

	ULONG oldLen;
	ULONG oldAccess;

	NTSTATUS st;
	MEMORY_BASIC_INFORMATION memInfo;

	ntsc_t *ntfp = ntdll_getFP();

	st = ntfp->FP_NtQueryVirtualMemory(XbNtCurrentProcess(), old_address, MemoryBasicInformation, &memInfo, sizeof(memInfo), NULL);
	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_FILE_LOCK_CONFLICT:
			errno = EAGAIN;
			return MAP_FAILED;
		default:
			errno = EINVAL;
			return MAP_FAILED;
		}
	}

	if (memInfo.State != MEM_COMMIT || memInfo.Type != MEM_MAPPED) {
		errno = EFAULT;
		return MAP_FAILED;
	}

	oldAddr = memInfo.AllocationBase;
	oldLen = memInfo.RegionSize;
	oldAccess = memInfo.AllocationProtect;

	if (old_address != oldAddr && old_size != oldLen) {
		errno = EFAULT;
		return MAP_FAILED;
	}

	if ((flags & 0x02) == MREMAP_FIXED && (flags & 0x01) != MREMAP_MAYMOVE) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	// FIXME
	// FIXME
	// FIXME
	// the constraints are too strict,
	// consider it later!!!
	st = ntfp->FP_NtAllocateVirtualMemory(XbNtCurrentProcess(), &newAddr, 0, &newSize, MEM_COMMIT, oldAccess);
	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_CONFLICTING_ADDRESSES:
			errno = ENOMEM;
			return MAP_FAILED;
		case STATUS_INVALID_ADDRESS:
		default:
			errno = EFAULT;
			return MAP_FAILED;
		}
	}

	errno = 0;
	return newAddr;
}
