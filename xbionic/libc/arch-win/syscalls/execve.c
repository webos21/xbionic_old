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

#define MAX_ARG_SIZE   (32768)

// int execve(const char *filename, char *const argv[], char *const envp[]);
int execve(const char *filename, char *const argv[], char *const envp[]) {
	int exeRet;
	int idx;
	char *psz;

	NTSTATUS st;

	UNICODE_STRING dosName;
	UNICODE_STRING imgName;
	UNICODE_STRING cmdLine;

	PUNICODE_STRING pCmd = NULL;
	PVOID pEnv = NULL;

	RTL_USER_PROCESS_PARAMETERS *pparam = NULL;
	RTL_USER_PROCESS_INFORMATION pinfo;

	ntsc_t *ntfp = ntdll_getFP();

	// prepare the resources
	ntfp->FP_RtlCreateUnicodeStringFromAsciiz(&dosName, filename);
	ntfp->FP_RtlDosPathNameToNtPathName_U(dosName.Buffer, &imgName, NULL, NULL);
	if (argv != NULL) {
		ANSI_STRING tmpcmd;

		tmpcmd.Length = 0;
		tmpcmd.MaximumLength = MAX_ARG_SIZE;
		tmpcmd.Buffer = (PSTR) ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, MAX_ARG_SIZE);
		ntfp->FP_RtlZeroMemory(tmpcmd.Buffer, MAX_ARG_SIZE);

		idx = 0;
		while ((psz = argv[idx++]) != NULL) {
			st = ntfp->FP_RtlAppendAsciizToString(&tmpcmd, "\"");
			st = ntfp->FP_RtlAppendAsciizToString(&tmpcmd, psz);
			st = ntfp->FP_RtlAppendAsciizToString(&tmpcmd, "\" ");
		}
		ntfp->FP_RtlAnsiStringToUnicodeString(&cmdLine, &tmpcmd, TRUE);
		pCmd = &cmdLine;
		ntfp->FP_RtlFreeHeap(XbRtlGetProcessHeap(ntfp), 0, tmpcmd.Buffer);
	}
	if (envp != NULL) {
		ntfp->FP_RtlCreateEnvironment(FALSE, &pEnv);
		idx = 0;
		while ((psz = envp[idx++]) != NULL) {
			int x = 0;
			char *key = psz;
			char *val = NULL;
			while ((*key) != '\0') {
				if ((*key) == '=') {
					x = 1;
					break;
				}
				key++;
			}
			if (x) {
				ANSI_STRING strKey;

				UNICODE_STRING envKey;
				UNICODE_STRING envVal;

				strKey.Length = (USHORT)(key - psz);
				strKey.MaximumLength = strKey.Length + 1;
				strKey.Buffer = psz;

				val = (char *)(key+1);
				ntfp->FP_RtlAnsiStringToUnicodeString(&envKey, &strKey, TRUE);
				ntfp->FP_RtlCreateUnicodeStringFromAsciiz(&envVal, val);
				ntfp->FP_RtlSetEnvironmentVariable(&pEnv, &envKey, &envVal);
				ntfp->FP_RtlFreeUnicodeString(&envVal);
				ntfp->FP_RtlFreeUnicodeString(&envKey);
			}
		}
	}

	// Init ProcessParam
	st = ntfp->FP_RtlCreateProcessParameters(&pparam, &imgName, NULL, NULL, pCmd, pEnv, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(st)) {
		ntfp->FP_DbgPrint("Fail to create the ProcessParameters!!!\n");
	}

	// Create Process
 	st = ntfp->FP_RtlCreateUserProcess(&imgName, 0, pparam, NULL, NULL, NULL, FALSE, NULL, NULL, &pinfo);
	if (!NT_SUCCESS(st)) {
		ntfp->FP_DbgPrint("error %x\n", st);
		switch (st) {
		case STATUS_OBJECT_PATH_SYNTAX_BAD:
			errno = ENOENT;
			break;
		case STATUS_INVALID_PARAMETER:
		default:
			errno = EACCES;
			break;
		}
	} else {
		PROCESS_BASIC_INFORMATION pbi;

		// Main Thread is suspended, so we must resume the thread!!
		ntfp->FP_NtResumeThread(pinfo.ThreadHandle, NULL);

		// execve will not return, just exit
		ntfp->FP_NtWaitForSingleObject(pinfo.ProcessHandle, FALSE, NULL);
		ntfp->FP_NtQueryInformationProcess(pinfo.ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
		exeRet = (int) pbi.ExitStatus;
		errno = 0;
	}

	// if it is success, these codes are not executed.
	// Release the resources
	if (pparam != NULL) {
		ntfp->FP_RtlDestroyProcessParameters(pparam);
		pparam = NULL;
	}
	if (pEnv != NULL) {
		ntfp->FP_RtlDestroyEnvironment(pEnv);
		pEnv = NULL;
	}
	if (pCmd != NULL) {
		ntfp->FP_RtlFreeUnicodeString(&cmdLine);
	}
	ntfp->FP_RtlFreeUnicodeString(&imgName);
	ntfp->FP_RtlFreeUnicodeString(&dosName);

	if (errno != 0) {
		return -1;
	} else {
		// execve will not return, just exit
		ntfp->FP_RtlExitUserProcess(exeRet);
		return 0; // for compiler happy
	}
}
