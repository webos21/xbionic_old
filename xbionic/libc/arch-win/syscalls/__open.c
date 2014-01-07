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
#include <ntsock.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "___fd_win.h"

// write to a file descriptor
// ref {
//     http://linux.die.net/man/2/open
// }
int __open(const char *pathname, int flags, int mode) {
	xb_fd_t pfd;

	NTSTATUS st;

	ACCESS_MASK desiredAccess = 0;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	ULONG fileAttributes = FILE_ATTRIBUTE_NORMAL;
	ULONG shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG createDisposition = 0;
	ULONG createOptions = 0;
	// FILE_FULL_EA_INFORMATION eaBuf; // Not Needed
	
	UNICODE_STRING dosPath;
	UNICODE_STRING ntPath;

	ntsc_t *ntfp = ntdll_getFP();

	if (pathname == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((flags & O_EXCL) && !(flags & O_CREAT)) {
		errno = EACCES;
		return -1;
	}
	if ((flags & O_DIRECTORY) && ((flags & O_WRONLY) || (flags & O_RDWR))) {
		errno = EISDIR;
		return -1;
	}

	desiredAccess = FILE_GENERIC_READ;
	if (flags & O_WRONLY) {
		desiredAccess = FILE_GENERIC_WRITE;
	}
	if (flags & O_RDWR) {
		desiredAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	}
	// - O_SYNC is the default value of FILE_GENERIC_xxx
	//if (flags & O_SYNC) {
	//	desiredAccess |= SYNCHRONIZE;
	//}


	if (flags & O_CREAT) {
		if (flags & O_EXCL) {
			/* only create new if file does not already exist */
			createDisposition = FILE_CREATE;
		} else if (flags & O_TRUNC) {
			/* truncate existing file or create new */
			createDisposition = FILE_SUPERSEDE;
		} else {
			/* open existing but create if necessary */
			createDisposition = FILE_OPEN_IF;
		}
	} else if (flags & O_TRUNC) {
		/* only truncate if file already exists */
		createDisposition = FILE_OVERWRITE;
	} else {
		/* only open if file already exists */
		createDisposition = FILE_OPEN;
	}

	if (flags & O_DIRECTORY) {
		fileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		createOptions |= FILE_DIRECTORY_FILE | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
	} else {
		createOptions |= FILE_SYNCHRONOUS_IO_ALERT;
	}

	if (flags & O_DIRECT) {
		desiredAccess ^= FILE_APPEND_DATA;
		createOptions |= FILE_NO_INTERMEDIATE_BUFFERING;
	}

	// mode : permission is not processed!!

	if (!ntfp->FP_RtlCreateUnicodeStringFromAsciiz(&dosPath, pathname)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (!ntfp->FP_RtlDosPathNameToNtPathName_U(dosPath.Buffer, &ntPath, NULL, NULL)) {
		ntfp->FP_RtlFreeUnicodeString(&dosPath);
		errno = ENAMETOOLONG;
		return -1;
	}

	oa.Length = sizeof(oa);
	oa.RootDirectory = NULL;
	oa.ObjectName = &ntPath;
	oa.Attributes = 0;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	iosb.Status = 0;
	iosb.Pointer = NULL;
	iosb.Information = 0;

	st = ntfp->FP_NtCreateFile(&pfd.desc.f.fd, desiredAccess, &oa, &iosb, NULL,
								fileAttributes, shareAccess, createDisposition, createOptions,
								NULL, 0);
	// Release string memory, first!
	ntfp->FP_RtlFreeUnicodeString(&ntPath);
	ntfp->FP_RtlFreeUnicodeString(&dosPath);

	if (!NT_SUCCESS(st)) {
		switch (st) {
		case STATUS_OBJECT_NAME_NOT_FOUND:
			errno = ENOENT;
			return -1;
		case STATUS_OBJECT_NAME_COLLISION:
			errno = EEXIST;
			return -1;
		case STATUS_EA_LIST_INCONSISTENT:
			errno = EINVAL;
			return -1;
		default:
			errno = EACCES;
			return -1;
		}
	}

	pfd.fdtype = (flags & O_DIRECTORY) ? XB_FD_TYPE_DIR : XB_FD_TYPE_FILE;
	pfd.desc.f.flag = flags;
	pfd.desc.f.mode = mode;
	pfd.desc.f.path = (char *)pathname;

	return xb_fd_open(&pfd);
}
