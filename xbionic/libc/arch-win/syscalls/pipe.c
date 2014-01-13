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
#include <unistd.h>
#include <fcntl.h>

#include "___fd_win.h"


LONG _g_pipeId = 0;


// create pipe
// - [0] : read / [1] : write
// ref {
//     http://linux.die.net/man/2/pipe2
//     http://msdn.microsoft.com/en-us/library/windows/desktop/aa365152(v=vs.85).aspx
// }
int pipe(int pipefd[2]) {
	if (pipefd == NULL) {
		errno = EFAULT;
		return -1;
	} else {
		NTSTATUS ret;

		DWORD bufLen;
		CHAR intBuf[16];
		CHAR dosNameBuf[64];
		ANSI_STRING dosName;
		WCHAR pipeNameBuf[64];
		UNICODE_STRING pipeName;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK iosb;
		LARGE_INTEGER timeOut;
		HANDLE hrPipe;
		HANDLE hwPipe;
		LONG pipeId;
		ULONG attr;
		PSECURITY_DESCRIPTOR sd = NULL;

		xb_fd_t pfd[2];

		ntsc_t *ntfp = ntdll_getFP();

		// Set the timeout to 120 seconds
		timeOut.QuadPart = -1200000000;

		// Use default buffer size if desired
		bufLen = 0x1000;

		// Increase the Pipe ID
		pipeId = _g_pipeId++;

		// Create the pipe name
		dosName.Buffer = dosNameBuf;
		dosName.Length = 0;
		dosName.MaximumLength = sizeof(dosNameBuf);

		pipeName.Buffer = pipeNameBuf;
		pipeName.Length = 0;
		pipeName.MaximumLength = sizeof(pipeNameBuf);

		ntfp->FP_RtlZeroMemory(dosNameBuf, sizeof(dosNameBuf));
		ntfp->FP_RtlAppendAsciizToString(&dosName, "\\Device\\NamedPipe\\Win32Pipes.");
		ntfp->FP_RtlZeroMemory(intBuf, sizeof(intBuf));
		ntfp->FP_RtlIntegerToChar((ULONG)XbNtCurrentTeb()->Cid.UniqueProcess, 16, 8, intBuf);
		ntfp->FP_RtlAppendAsciizToString(&dosName, intBuf);
		ntfp->FP_RtlAppendAsciizToString(&dosName, ".");
		ntfp->FP_RtlZeroMemory(intBuf, sizeof(intBuf));
		ntfp->FP_RtlIntegerToChar(pipeId, 16, 8, intBuf);
		ntfp->FP_RtlAppendAsciizToString(&dosName, intBuf);

		ntfp->FP_RtlZeroMemory(pipeNameBuf, sizeof(pipeNameBuf));
		ntfp->FP_RtlAnsiStringToUnicodeString(&pipeName, &dosName, FALSE);

		// Always use case insensitive
		attr = OBJ_CASE_INSENSITIVE;

		// Initialize the attributes
		oa.Length = sizeof(oa);
		oa.RootDirectory = NULL;
		oa.ObjectName = &pipeName;
		oa.Attributes = attr;
		oa.SecurityDescriptor = sd;
		oa.SecurityQualityOfService = NULL;

		// Create the named pipe
		ret = ntfp->FP_NtCreateNamedPipeFile(&hrPipe,
			FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
			&oa,
			&iosb,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_CREATE,
			FILE_SYNCHRONOUS_IO_NONALERT,
			FILE_PIPE_BYTE_STREAM_TYPE,
			FILE_PIPE_BYTE_STREAM_MODE,
			FILE_PIPE_QUEUE_OPERATION,
			1,
			bufLen,
			bufLen,
			&timeOut);
		if (!NT_SUCCESS(ret)) {
			switch (ret) {
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		}

		// Now try opening it for write access
		ret = ntfp->FP_NtOpenFile(&hwPipe,
			FILE_GENERIC_WRITE | SYNCHRONIZE,
			&oa,
			&iosb,
			FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
		if (!NT_SUCCESS(ret)) {
			ntfp->FP_NtClose(hrPipe);
			switch (ret) {
			case STATUS_INVALID_PARAMETER:
			default:
				errno = EINVAL;
				return -1;
			}
		}

		// Set the result
		pfd[0].desc.f.fd = hrPipe;
		pfd[0].fdtype = XB_FD_TYPE_PIPE;
		pfd[0].desc.f.flag = O_RDONLY;
		pfd[0].desc.f.mode = 00400;
		pfd[0].desc.f.path = dosName.Buffer;

		pfd[1].desc.f.fd = hwPipe;
		pfd[1].fdtype = XB_FD_TYPE_PIPE;
		pfd[1].desc.f.flag = O_WRONLY;
		pfd[1].desc.f.mode = 00200;
		pfd[1].desc.f.path = dosName.Buffer;

		pipefd[0] = xb_fd_open(&pfd[0]);
		pipefd[1] = xb_fd_open(&pfd[1]);

		errno = 0;
		return 0;
	}
}
