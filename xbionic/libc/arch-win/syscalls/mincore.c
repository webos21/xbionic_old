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

// determine whether pages are resident in memory
// - mincore() is not specified in POSIX.1-2001, and it is not available on all UNIX implementations. 
// ref {
//     http://linux.die.net/man/2/mincore
//     http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
//     http://insights.oetiker.ch/linux/fadvise/
// }
// usage {
//     mincore_vec = calloc(1, (file_stat.st_size+page_size-1)/page_size);
//     mincore(file_mmap, file_stat.st_size, mincore_vec);
//     for (page_index = 0; page_index <= file_stat.st_size/page_size; page_index++) {
//         if (mincore_vec[page_index]&1) {
//             printf("%lu ", (unsigned long)page_index);
//         }
//     }
// }
int mincore(void *addr, size_t length, unsigned char *vec) {
	NTSTATUS st;
	MEMORY_BASIC_INFORMATION memInfo;

	ntsc_t *ntfp = ntdll_getFP();

	if (vec == NULL) {
		errno = EFAULT;
		return -1;
	}

	st = ntfp->FP_NtQueryVirtualMemory(XbNtCurrentProcess(), addr, MemoryBasicInformation, &memInfo, sizeof(memInfo), NULL);
	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_FILE_LOCK_CONFLICT:
			errno = ENOMEM;
			return -1;
		default:
			errno = EINVAL;
			return -1;
		}
	}

	if (memInfo.State == MEM_FREE) {
		errno = ENOMEM;
		return -1;
	}

	// FIXME
	// FIXME
	// FIXME
	vec[0] = 0x01;

	errno = 0;
	return 0;
}
