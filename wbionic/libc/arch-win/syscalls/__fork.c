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

#include <errno.h>
#include <ntdll.h>

int __fork(void) {
	NTSTATUS status;
	SECURITY_ATTRIBUTES sa;
	RTL_USER_PROCESS_INFORMATION *pi;

	int pid = -1;

	ntsc_t *ntfp = ntdll_getFP();

	sa.nLength = sizeof sa;
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	pi = ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, 4096);
	ntfp->FP_RtlZeroMemory(pi, 4096);

	status = ntfp->FP_RtlCloneUserProcess(
			RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
					| RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE, NULL, NULL, NULL,
			pi);

	// backup the pid and release heap
	pid = (int)pi->ClientId.UniqueProcess;
	ntfp->FP_RtlFreeHeap(XbRtlGetProcessHeap(ntfp), 0, pi);

	switch (status) {
	case STATUS_SUCCESS :
		errno = 0;
		return pid;
	case STATUS_PROCESS_CLONED:
		errno = 0;
		return 0;
	default:
		errno = status;
		return -1;
	}
}
