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

// give advice about use of memory
// - do nothing : just check the arguments
// ref {
//     http://linux.die.net/man/2/madvise
// }
int madvise(const void *addr, size_t length, int advice) {
	if (addr == NULL || length == 0) {
		errno = EINVAL;
		return -1;
	}

	switch (advice) {
	case MADV_NORMAL:       // 0
	case MADV_RANDOM:       // 1
	case MADV_SEQUENTIAL:   // 2
	case MADV_WILLNEED:     // 3
	case MADV_DONTNEED:     // 4
	case MADV_REMOVE:       // 9
	case MADV_DONTFORK:     // 10
	case MADV_DOFORK:       // 11
	case MADV_HWPOISON:     // 100
	case MADV_SOFT_OFFLINE: // 101
	case MADV_MERGEABLE:    // 12
	case MADV_UNMERGEABLE:  // 13
	case MADV_HUGEPAGE:     // 14
	case MADV_NOHUGEPAGE:   // 15
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	errno = 0;
	return 0;
}
