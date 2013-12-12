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
#include <dlfcn.h>

static void *_g_ntdll = NULL;
static ntsc_t _g_ntfp;

ntsc_t *ntdll_getFP() {
	if (_g_ntdll == NULL ) {
		// load the [ntdll.dll]
		_g_ntdll = dlopen("ntdll.dll", 0);
		if (NULL == _g_ntdll) {
			printf("cannot load [ntdll.dll]");
		}

		// mapping the [ntdll.dll] APIs

		/////////////////////
		// Process ENV Block
		/////////////////////

		_g_ntfp.FP_RtlGetCurrentPeb = dlsym(_g_ntdll, "RtlGetCurrentPeb");


		/////////////////////
		// Debug Functions
		/////////////////////

		_g_ntfp.FP_DbgPrint = dlsym(_g_ntdll, "DbgPrint");


		/////////////////////
		// Exit Functions
		/////////////////////

		_g_ntfp.FP_RtlExitUserProcess = dlsym(_g_ntdll, "RtlExitUserProcess");


		/////////////////////
		// Thread_Exit Functions
		/////////////////////

		_g_ntfp.FP_RtlExitUserThread = dlsym(_g_ntdll, "RtlExitUserThread");


		/////////////////////
		// Fork Functions
		/////////////////////

		_g_ntfp.FP_RtlCreateProcessParameters = dlsym(_g_ntdll, "RtlCreateProcessParameters");
		_g_ntfp.FP_RtlDestroyProcessParameters = dlsym(_g_ntdll, "RtlDestroyProcessParameters");
		_g_ntfp.FP_RtlCreateUserProcess = dlsym(_g_ntdll, "RtlCreateUserProcess");

		_g_ntfp.FP_CsrClientCallServer = dlsym(_g_ntdll, "CsrClientCallServer");

		_g_ntfp.FP_NtQueryInformationProcess = dlsym(_g_ntdll, "NtQueryInformationProcess");

		_g_ntfp.FP_RtlCloneUserProcess = dlsym(_g_ntdll, "RtlCloneUserProcess");

		_g_ntfp.FP_RtlUpdateClonedCriticalSection = dlsym(_g_ntdll, "RtlUpdateClonedCriticalSection");
		_g_ntfp.FP_RtlUpdateClonedSRWLock = dlsym(_g_ntdll, "RtlUpdateClonedSRWLock");


		/////////////////////
		// Memory Functions
		/////////////////////

		_g_ntfp.FP_RtlAllocateHeap = dlsym(_g_ntdll, "RtlAllocateHeap");
		_g_ntfp.FP_RtlFreeHeap = dlsym(_g_ntdll, "RtlFreeHeap");
		_g_ntfp.FP_RtlZeroMemory = dlsym(_g_ntdll, "RtlZeroMemory");
		_g_ntfp.FP_RtlFillMemory = dlsym(_g_ntdll, "RtlFillMemory");
		_g_ntfp.FP_RtlCompareMemory = dlsym(_g_ntdll, "RtlCompareMemory");
#ifndef _WIN64
		// Win32 ntdll.dll has no RtlCopyMemory!!!
		_g_ntfp.FP_RtlCopyMemory = dlsym(_g_ntdll, "RtlMoveMemory");
#else
		_g_ntfp.FP_RtlCopyMemory = dlsym(_g_ntdll, "RtlCopyMemory");
#endif
		_g_ntfp.FP_RtlMoveMemory = dlsym(_g_ntdll, "RtlMoveMemory");


		/////////////////////
		// String Functions
		/////////////////////

		_g_ntfp.FP_RtlInitString = dlsym(_g_ntdll, "RtlInitString");
		_g_ntfp.FP_RtlInitUnicodeString = dlsym(_g_ntdll, "RtlInitUnicodeString");

		_g_ntfp.FP_RtlAnsiStringToUnicodeSize = dlsym(_g_ntdll, "RtlAnsiStringToUnicodeSize");
		_g_ntfp.FP_RtlAnsiStringToUnicodeString = dlsym(_g_ntdll, "RtlAnsiStringToUnicodeString");

		_g_ntfp.FP_RtlUnicodeStringToAnsiSize = dlsym(_g_ntdll, "RtlUnicodeStringToAnsiSize");
		_g_ntfp.FP_RtlUnicodeStringToAnsiString = dlsym(_g_ntdll, "RtlUnicodeStringToAnsiString");

		_g_ntfp.FP_RtlCopyString = dlsym(_g_ntdll, "RtlCopyString");
		_g_ntfp.FP_RtlCopyUnicodeString = dlsym(_g_ntdll, "RtlCopyUnicodeString");

		_g_ntfp.FP_RtlEqualString = dlsym(_g_ntdll, "RtlEqualString");
		_g_ntfp.FP_RtlEqualUnicodeString = dlsym(_g_ntdll, "RtlEqualUnicodeString");

		_g_ntfp.FP_RtlCompareString = dlsym(_g_ntdll, "RtlCompareString");
		_g_ntfp.FP_RtlCompareUnicodeString = dlsym(_g_ntdll, "RtlCompareUnicodeString");

		_g_ntfp.FP_RtlUpperString = dlsym(_g_ntdll, "RtlUpperString");
		_g_ntfp.FP_RtlUpcaseUnicodeString = dlsym(_g_ntdll, "RtlUpcaseUnicodeString");

		_g_ntfp.FP_RtlIntegerToChar = dlsym(_g_ntdll, "RtlIntegerToChar");
		_g_ntfp.FP_RtlIntegerToUnicodeString = dlsym(_g_ntdll, "RtlIntegerToUnicodeString");

		_g_ntfp.FP_RtlCharToInteger = dlsym(_g_ntdll, "RtlCharToInteger");
		_g_ntfp.FP_RtlUnicodeStringToInteger = dlsym(_g_ntdll, "RtlUnicodeStringToInteger");

		_g_ntfp.FP_RtlFreeAnsiString = dlsym(_g_ntdll, "RtlFreeAnsiString");
		_g_ntfp.FP_RtlFreeUnicodeString = dlsym(_g_ntdll, "RtlFreeUnicodeString");

	}
	return &_g_ntfp;
}
