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

#include "___fd_win.h"

static HANDLE NTAPI XbCreateFileMapping(HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCWSTR lpName);

static LPVOID NTAPI XbMapViewOfFileEx(HANDLE hFileMappingObject,
	DWORD dwDesiredAccess,
	DWORD dwFileOffsetHigh,
	DWORD dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap,
	LPVOID lpBaseAddress);

// map files or devices into memory
// ref {
//     http://linux.die.net/man/2/mmap2
// }
void *__mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	DWORD fmaccess = 0;
	DWORD mvaccess = 0;
	HANDLE fhnd = NULL;

	void *mapAddr = NULL;
	void *memAddr = NULL;

	DWORD len_hi = 0;
	DWORD len_lo = 0;

	DWORD pos_hi = 0;
	DWORD pos_lo = 0;

	NTSTATUS st;

	BOOLEAN anon = (flags & MAP_ANONYMOUS);

	ntsc_t *ntfp = ntdll_getFP();

	if ((flags & MAP_ANONYMOUS) != MAP_ANONYMOUS && (fd < 0)) {
		errno = EBADF;
		return MAP_FAILED;
	}

	if (length == 0) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (prot & PROT_EXEC) {
		mvaccess |= FILE_MAP_EXECUTE;
	}
	if (prot & PROT_WRITE) {
		mvaccess |= FILE_MAP_WRITE;
	}
	if (prot & PROT_READ) {
		mvaccess |= FILE_MAP_READ;
	}

	if ((flags & 0x07)!= MAP_PRIVATE && (flags & 0x07) != MAP_SHARED) {
		errno = EINVAL;
		return MAP_FAILED;
	}

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
		return MAP_FAILED;
	}

#ifdef _WIN64
	len_hi = (DWORD)((length>>0x20)&0x7fffffff);
	len_lo = (DWORD)(length&0xffffffff);
	pos_hi = (DWORD)((offset>>0x20)&0x7fffffff);
	pos_lo = (DWORD)(offset&0xffffffff);
#else // !_WIN64
	len_hi = 0;
	len_lo = length;
	pos_hi = 0;
	pos_lo = offset;
#endif // _WIN64

	if (anon) {
		fhnd = XbCreateFileMapping(INVALID_HANDLE_VALUE, NULL, fmaccess|SEC_RESERVE, len_hi, len_lo, NULL);
		if (fhnd == NULL) {
			errno = EFAULT;
			return MAP_FAILED;
		}
		mapAddr = XbMapViewOfFileEx(fhnd, mvaccess, pos_hi, pos_lo, length, addr);
		if (mapAddr == NULL) {
			ntfp->FP_NtClose(fhnd);
			errno = EFAULT;
			return MAP_FAILED;
		} else {
			memAddr = mapAddr;
			st = ntfp->FP_NtAllocateVirtualMemory(XbNtCurrentProcess(), &memAddr, 0, (PSIZE_T)&length, MEM_COMMIT, fmaccess);
			ntfp->FP_NtClose(fhnd);
			if (!NT_SUCCESS(st)) {
				switch (st) {
				case STATUS_INVALID_ADDRESS:
				default:
					errno = EFAULT;
					return MAP_FAILED;
				}
			}
			return memAddr;
		}
	} else {
		xb_fd_t *fdesc = xb_fd_get(fd);
		if (fdesc == NULL) {
			errno = EBADF;
			return MAP_FAILED;
		}
		fhnd = XbCreateFileMapping(fdesc->desc.f.fd, NULL, fmaccess, 0, 0, NULL);
		if (fhnd == NULL) {
			errno = EBADF;
			return MAP_FAILED;
		}
		mapAddr = XbMapViewOfFileEx(fhnd, mvaccess, pos_hi, pos_lo, length, addr);
		if (mapAddr == NULL) {
			ntfp->FP_NtClose(fhnd);
			errno = EFAULT;
			return MAP_FAILED;
		} else {
			memAddr = mapAddr;
			ntfp->FP_NtClose(fhnd);
			return memAddr;
		}
	}
}

static HANDLE NTAPI XbCreateFileMapping(HANDLE hFile,
			LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
			DWORD flProtect,
			DWORD dwMaximumSizeHigh,
			DWORD dwMaximumSizeLow,
			LPCWSTR lpName
	) {
	NTSTATUS Status;
	HANDLE SectionHandle;
	OBJECT_ATTRIBUTES LocalAttributes;
	POBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING SectionName;
	ACCESS_MASK DesiredAccess;
	LARGE_INTEGER LocalSize;
	PLARGE_INTEGER SectionSize = NULL;
	ULONG Attributes;

	ntsc_t *ntfp = ntdll_getFP();

	// Set default access
	DesiredAccess = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ;

	// Get the attributes for the actual allocation and cleanup flProtect
	Attributes = flProtect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_NOCACHE | SEC_COMMIT | SEC_LARGE_PAGES);
	flProtect ^= Attributes;

	// If the caller didn't say anything, assume SEC_COMMIT
	if (!Attributes) Attributes = SEC_COMMIT;

	// Now check if the caller wanted write access
	if (flProtect == PAGE_READWRITE) {
		DesiredAccess |= SECTION_MAP_WRITE;
	} else if (flProtect == PAGE_EXECUTE_READWRITE)	{
		DesiredAccess |= (SECTION_MAP_WRITE | SECTION_MAP_EXECUTE);
	} else if (flProtect == PAGE_EXECUTE_READ) {
		DesiredAccess |= SECTION_MAP_EXECUTE;
	} else if ((flProtect != PAGE_READONLY) && (flProtect != PAGE_WRITECOPY)) {
		return NULL;
	}

	// Now check if we got a name
	if (lpName) ntfp->FP_RtlInitUnicodeString(&SectionName, lpName);

	// Now convert the object attributes
	ObjectAttributes = &LocalAttributes;
	ObjectAttributes->Length = sizeof(LocalAttributes);
	ObjectAttributes->RootDirectory = NULL;
	ObjectAttributes->ObjectName = (lpName) ? &SectionName : NULL;
	ObjectAttributes->Attributes = (ULONG)lpFileMappingAttributes;
	ObjectAttributes->SecurityDescriptor = NULL;
	ObjectAttributes->SecurityQualityOfService = NULL;

	// Check if we got a size
	if (dwMaximumSizeLow || dwMaximumSizeHigh) {
		// Use a LARGE_INTEGER and convert
		SectionSize = &LocalSize;
		SectionSize->u.LowPart = dwMaximumSizeLow;
		SectionSize->u.HighPart = dwMaximumSizeHigh;
	}

	// Make sure the handle is valid
	if (hFile == INVALID_HANDLE_VALUE) {
		// It's not, we'll only go on if we have a size
		hFile = NULL;
		if (!SectionSize) {
			// No size, so this isn't a valid non-mapped section
			return NULL;
		}
	}

	// Now create the actual section
	Status = ntfp->FP_NtCreateSection(&SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		SectionSize,
		flProtect,
		Attributes,
		hFile);
	if (!NT_SUCCESS(Status)) {
		// We failed
		return NULL;
	} else if (Status == STATUS_OBJECT_NAME_EXISTS) {
		// already exists
	} else {
		// success
	}

	// Return the section
	return SectionHandle;
}


static LPVOID NTAPI XbMapViewOfFileEx(HANDLE hFileMappingObject,
		DWORD dwDesiredAccess,
		DWORD dwFileOffsetHigh,
		DWORD dwFileOffsetLow,
		SIZE_T dwNumberOfBytesToMap,
		LPVOID lpBaseAddress
	) {
	NTSTATUS Status;
	LARGE_INTEGER SectionOffset;
	SIZE_T ViewSize;
	ULONG Protect;
	LPVOID ViewBase;

	ntsc_t *ntfp = ntdll_getFP();

	/* Convert the offset */
	SectionOffset.u.LowPart = dwFileOffsetLow;
	SectionOffset.u.HighPart = dwFileOffsetHigh;

	/* Save the size and base */
	ViewBase = lpBaseAddress;
	ViewSize = dwNumberOfBytesToMap;

	/* Convert flags to NT Protection Attributes */
	if (dwDesiredAccess == FILE_MAP_COPY) {
		Protect = PAGE_WRITECOPY;
	} else if (dwDesiredAccess & FILE_MAP_WRITE) {
		Protect = (dwDesiredAccess & FILE_MAP_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
	} else if (dwDesiredAccess & FILE_MAP_READ) {
		Protect = (dwDesiredAccess & FILE_MAP_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY;
	} else {
		Protect = PAGE_NOACCESS;
	}

	/* Map the section */
	Status = ntfp->FP_NtMapViewOfSection(hFileMappingObject,
		XbNtCurrentProcess(),
		&ViewBase,
		0,
		0,
		&SectionOffset,
		&ViewSize,
		ViewShare,
		0,
		Protect);
	if (!NT_SUCCESS(Status)) {
		switch (Status) {
		case STATUS_INVALID_VIEW_SIZE:
			errno = EINVAL;
			return NULL;
		}
	}

	/* Return the base */
	return ViewBase;
}

