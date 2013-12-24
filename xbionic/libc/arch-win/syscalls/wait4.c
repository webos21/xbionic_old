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

#define P_ALL  0
#define P_PID  1
#define P_PGID 2

// pid_t wait4(pid_t pid, int *status, int options, struct rusage *ru);
int wait4(int pid, int *status, int options, void *ru) {
	// Only cover that the pid is specified. (pid == -1 is not implemented!!)
	// we can implement the full specification with ProcessEnumeration

	HANDLE hpid;
	OBJECT_ATTRIBUTES oa = {0, NULL, NULL, 0, NULL, NULL};
	CLIENT_ID cid;
	PROCESS_BASIC_INFORMATION pbi;

	ntsc_t *ntfp = ntdll_getFP();

	oa.Length = sizeof(oa);
	cid.UniqueProcess = (HANDLE) pid;
	cid.UniqueThread = NULL;
	ntfp->FP_NtOpenProcess(&hpid, PROCESS_ALL_ACCESS, &oa, &cid);
	ntfp->FP_NtWaitForSingleObject(hpid, FALSE, NULL); // timeout(NULL) : INFINITE
	ntfp->FP_NtQueryInformationProcess(hpid, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	(*status) = (int) pbi.ExitStatus;
	ntfp->FP_NtClose(hpid);
	errno = 0;
	return 0;
}
