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

/************************************************************************/
/* In case of MINGW-Builds, libgcc.a has the [mprotect] function.       */
/* So, we only enable the [mprotect] function on VS2010.                */
/************************************************************************/

#ifdef _MSC_VER

#include <ntdll.h>
#include <errno.h>
#include <sys/mman.h>

// set protection on a region of memory
// ref {
//     http://linux.die.net/man/2/mprotect
// }
int mprotect(const void *addr, size_t len, int prot) {
	ULONG fmaccess = 0;
	ULONG oldflag = 0;
	ULONG memLen = len;

	NTSTATUS st;
	ntsc_t *ntfp = ntdll_getFP();

	switch (prot) {
	case 0x01: // Read
		fmaccess = PAGE_READONLY;
		break;
	case 0x02: // Write
		fmaccess = PAGE_READWRITE;
		break;
	case 0x03: // Read/Write
		fmaccess = PAGE_READWRITE;
		break;
	case 0x04: // Exec
		fmaccess = PAGE_EXECUTE_READ;
		break;
	case 0x05: // Exec/Read
		fmaccess = PAGE_EXECUTE_READ;
		break;
	case 0x06: // Write/Exec
		fmaccess = PAGE_EXECUTE_READWRITE;
		break;
	case 0x07:
		fmaccess = PAGE_EXECUTE_READWRITE;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	st = ntfp->FP_NtProtectVirtualMemory(XbNtCurrentProcess(), (PVOID *)&addr, &memLen, fmaccess, &oldflag);
	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_SECTION_PROTECTION:
			errno = EACCES;
			return -1;
		case STATUS_CONFLICTING_ADDRESSES:
		case STATUS_INVALID_ADDRESS:
		default:
			errno = EINVAL;
			return -1;
		}
	}

	errno = 0;
	return 0;
}

#else  // !_MSC_VER

#endif // _MSC_VER