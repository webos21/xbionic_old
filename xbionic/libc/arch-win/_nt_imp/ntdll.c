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

//////////////////////////////////////////
// Forward Declarations (compiler happy)
//////////////////////////////////////////

extern int printf(const char *, ...);


//////////////////////////////////////////
// Static Variables
//////////////////////////////////////////

static void *_g_ntdll = NULL;
static ntsc_t _g_ntfp;


//////////////////////////////////////////
// Interface Functions
//////////////////////////////////////////

ntsc_t *ntdll_getFP() {
	if (NULL == _g_ntdll) {
		// load the [ntdll.dll]
		_g_ntdll = dlopen("ntdll.dll", 0);
		if (NULL == _g_ntdll) {
			printf("cannot load [ntdll.dll]");
			return NULL;
		}

		// mapping the [ntdll.dll] APIs


		/////////////////////
		// System
		/////////////////////

		_g_ntfp.FP_NtQuerySystemInformation = dlsym(_g_ntdll, "NtQuerySystemInformation");


		/////////////////////
		// Process ENV Block
		/////////////////////

		_g_ntfp.FP_RtlGetCurrentPeb = dlsym(_g_ntdll, "RtlGetCurrentPeb");


		/////////////////////
		// Context
		/////////////////////

		_g_ntfp.FP_RtlCaptureContext = dlsym(_g_ntdll, "RtlCaptureContext");
		_g_ntfp.FP_RtlActivateActivationContextUnsafeFast = dlsym(_g_ntdll, "RtlActivateActivationContextUnsafeFast");
		_g_ntfp.FP_RtlDeactivateActivationContextUnsafeFast = dlsym(_g_ntdll, "RtlDeactivateActivationContextUnsafeFast");


		/////////////////////
		// Debug Functions
		/////////////////////

		_g_ntfp.FP_DbgPrint = dlsym(_g_ntdll, "DbgPrint");

		_g_ntfp.FP_RtlCreateQueryDebugBuffer = dlsym(_g_ntdll, "RtlCreateQueryDebugBuffer");
		_g_ntfp.FP_RtlQueryProcessDebugInformation = dlsym(_g_ntdll, "RtlQueryProcessDebugInformation");
		_g_ntfp.FP_RtlDestroyQueryDebugBuffer = dlsym(_g_ntdll, "RtlDestroyQueryDebugBuffer");


		/////////////////////
		// Error Functions
		/////////////////////

		_g_ntfp.FP_RtlGetLastWin32Error = dlsym(_g_ntdll, "RtlGetLastWin32Error");
		_g_ntfp.FP_RtlSetLastWin32Error = dlsym(_g_ntdll, "RtlSetLastWin32Error");

		_g_ntfp.FP_RtlRaiseException = dlsym(_g_ntdll, "RtlRaiseException");
		_g_ntfp.FP_RtlRaiseStatus = dlsym(_g_ntdll, "RtlRaiseStatus");


		/////////////////////
		// Memory Functions
		/////////////////////

		_g_ntfp.FP_RtlAllocateHeap = dlsym(_g_ntdll, "RtlAllocateHeap");
		_g_ntfp.FP_RtlReAllocateHeap = dlsym(_g_ntdll, "RtlReAllocateHeap");
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

		_g_ntfp.FP_RtlFlushSecureMemoryCache = dlsym(_g_ntdll, "RtlFlushSecureMemoryCache");


		/////////////////////
		// Virtual Memory Functions
		/////////////////////

		_g_ntfp.FP_NtCreateSection = dlsym(_g_ntdll, "NtCreateSection");
		_g_ntfp.FP_NtMapViewOfSection = dlsym(_g_ntdll, "NtMapViewOfSection");
		_g_ntfp.FP_NtUnmapViewOfSection = dlsym(_g_ntdll, "NtUnmapViewOfSection");

		_g_ntfp.FP_NtAllocateVirtualMemory = dlsym(_g_ntdll, "NtAllocateVirtualMemory");
		_g_ntfp.FP_NtFreeVirtualMemory = dlsym(_g_ntdll, "NtFreeVirtualMemory");
		_g_ntfp.FP_NtFlushVirtualMemory = dlsym(_g_ntdll, "NtFlushVirtualMemory");

		_g_ntfp.FP_NtProtectVirtualMemory = dlsym(_g_ntdll, "NtProtectVirtualMemory");

		_g_ntfp.FP_NtQueryVirtualMemory = dlsym(_g_ntdll, "NtQueryVirtualMemory");

		_g_ntfp.FP_NtLockVirtualMemory = dlsym(_g_ntdll, "NtLockVirtualMemory");
		_g_ntfp.FP_NtUnlockVirtualMemory = dlsym(_g_ntdll, "NtUnlockVirtualMemory");

		_g_ntfp.FP_NtReadVirtualMemory = dlsym(_g_ntdll, "NtReadVirtualMemory");
		_g_ntfp.FP_NtWriteVirtualMemory = dlsym(_g_ntdll, "NtWriteVirtualMemory");


		/////////////////////
		// String Functions
		/////////////////////

		_g_ntfp.FP_RtlInitString = dlsym(_g_ntdll, "RtlInitString");
		_g_ntfp.FP_RtlInitUnicodeString = dlsym(_g_ntdll, "RtlInitUnicodeString");
		_g_ntfp.FP_RtlCreateUnicodeStringFromAsciiz = dlsym(_g_ntdll, "RtlCreateUnicodeStringFromAsciiz");

		_g_ntfp.FP_RtlAnsiStringToUnicodeSize = dlsym(_g_ntdll, "RtlAnsiStringToUnicodeSize");
		_g_ntfp.FP_RtlAnsiStringToUnicodeString = dlsym(_g_ntdll, "RtlAnsiStringToUnicodeString");

		_g_ntfp.FP_RtlUnicodeStringToAnsiSize = dlsym(_g_ntdll, "RtlUnicodeStringToAnsiSize");
		_g_ntfp.FP_RtlUnicodeStringToAnsiString = dlsym(_g_ntdll, "RtlUnicodeStringToAnsiString");

		_g_ntfp.FP_RtlCopyString = dlsym(_g_ntdll, "RtlCopyString");
		_g_ntfp.FP_RtlCopyUnicodeString = dlsym(_g_ntdll, "RtlCopyUnicodeString");

		_g_ntfp.FP_RtlAppendAsciizToString = dlsym(_g_ntdll, "RtlAppendAsciizToString");
		_g_ntfp.FP_RtlAppendStringToString = dlsym(_g_ntdll, "RtlAppendStringToString");
		_g_ntfp.FP_RtlAppendUnicodeStringToString = dlsym(_g_ntdll, "RtlAppendUnicodeStringToString");
		_g_ntfp.FP_RtlAppendUnicodeToString = dlsym(_g_ntdll, "RtlAppendUnicodeToString");
		_g_ntfp.FP_RtlMultiAppendUnicodeStringBuffer = dlsym(_g_ntdll, "RtlMultiAppendUnicodeStringBuffer");

		_g_ntfp.FP_RtlEqualString = dlsym(_g_ntdll, "RtlEqualString");
		_g_ntfp.FP_RtlEqualUnicodeString = dlsym(_g_ntdll, "RtlEqualUnicodeString");

		_g_ntfp.FP_RtlCompareString = dlsym(_g_ntdll, "RtlCompareString");
		_g_ntfp.FP_RtlCompareUnicodeString = dlsym(_g_ntdll, "RtlCompareUnicodeString");

		_g_ntfp.FP_RtlUpperString = dlsym(_g_ntdll, "RtlUpperString");
		_g_ntfp.FP_RtlUpcaseUnicodeString = dlsym(_g_ntdll, "RtlUpcaseUnicodeString");
		_g_ntfp.FP_RtlDowncaseUnicodeChar = dlsym(_g_ntdll, "RtlDowncaseUnicodeChar");
		_g_ntfp.FP_RtlDowncaseUnicodeString = dlsym(_g_ntdll, "RtlDowncaseUnicodeString");

		_g_ntfp.FP_RtlIntegerToChar = dlsym(_g_ntdll, "RtlIntegerToChar");
		_g_ntfp.FP_RtlIntegerToUnicodeString = dlsym(_g_ntdll, "RtlIntegerToUnicodeString");

		_g_ntfp.FP_RtlCharToInteger = dlsym(_g_ntdll, "RtlCharToInteger");
		_g_ntfp.FP_RtlUnicodeStringToInteger = dlsym(_g_ntdll, "RtlUnicodeStringToInteger");

		_g_ntfp.FP_RtlFreeAnsiString = dlsym(_g_ntdll, "RtlFreeAnsiString");
		_g_ntfp.FP_RtlFreeUnicodeString = dlsym(_g_ntdll, "RtlFreeUnicodeString");


		/////////////////////
		// Environment Functions
		/////////////////////

		_g_ntfp.FP_RtlCreateEnvironment = dlsym(_g_ntdll, "RtlCreateEnvironment");
		_g_ntfp.FP_RtlDestroyEnvironment = dlsym(_g_ntdll, "RtlDestroyEnvironment");
		_g_ntfp.FP_RtlExpandEnvironmentStrings_U = dlsym(_g_ntdll, "RtlExpandEnvironmentStrings_U");
		_g_ntfp.FP_RtlQueryEnvironmentVariable_U = dlsym(_g_ntdll, "RtlQueryEnvironmentVariable_U");
		_g_ntfp.FP_RtlSetCurrentEnvironment = dlsym(_g_ntdll, "RtlSetCurrentEnvironment");
		_g_ntfp.FP_RtlSetEnvironmentStrings = dlsym(_g_ntdll, "RtlSetEnvironmentStrings");
		_g_ntfp.FP_RtlSetEnvironmentVariable = dlsym(_g_ntdll, "RtlSetEnvironmentVariable");


		/////////////////////
		// Process Functions
		/////////////////////

		_g_ntfp.FP_RtlCreateProcessParameters = dlsym(_g_ntdll, "RtlCreateProcessParameters");
		_g_ntfp.FP_RtlDestroyProcessParameters = dlsym(_g_ntdll, "RtlDestroyProcessParameters");
		_g_ntfp.FP_RtlCreateUserProcess = dlsym(_g_ntdll, "RtlCreateUserProcess");

		_g_ntfp.FP_CsrClientCallServer = dlsym(_g_ntdll, "CsrClientCallServer");

		_g_ntfp.FP_NtQueryInformationProcess = dlsym(_g_ntdll, "NtQueryInformationProcess");

		_g_ntfp.FP_RtlCloneUserProcess = dlsym(_g_ntdll, "RtlCloneUserProcess");

		_g_ntfp.FP_RtlUpdateClonedCriticalSection = dlsym(_g_ntdll, "RtlUpdateClonedCriticalSection");
		_g_ntfp.FP_RtlUpdateClonedSRWLock = dlsym(_g_ntdll, "RtlUpdateClonedSRWLock");

		_g_ntfp.FP_RtlExitUserProcess = dlsym(_g_ntdll, "RtlExitUserProcess");

		_g_ntfp.FP_NtWaitForSingleObject = dlsym(_g_ntdll, "NtWaitForSingleObject");

		_g_ntfp.FP_NtOpenProcess = dlsym(_g_ntdll, "NtOpenProcess");
		_g_ntfp.FP_NtClose = dlsym(_g_ntdll, "NtClose");



		/////////////////////
		// Thread Functions
		/////////////////////

		_g_ntfp.FP_RtlCreateUserThread = dlsym(_g_ntdll, "RtlCreateUserThread");
		_g_ntfp.FP_RtlExitUserThread = dlsym(_g_ntdll, "RtlExitUserThread");
		_g_ntfp.FP_NtDelayExecution = dlsym(_g_ntdll, "NtDelayExecution");
		_g_ntfp.FP_NtSuspendThread = dlsym(_g_ntdll, "NtSuspendThread");
		_g_ntfp.FP_NtResumeThread = dlsym(_g_ntdll, "NtResumeThread");
		_g_ntfp.FP_NtOpenThread = dlsym(_g_ntdll, "NtOpenThread");
		_g_ntfp.FP_NtQueryInformationThread = dlsym(_g_ntdll, "NtQueryInformationThread");


		/////////////////////
		// CriticalSection Functions
		/////////////////////

		_g_ntfp.FP_RtlInitializeCriticalSection = dlsym(_g_ntdll, "RtlInitializeCriticalSection");
		_g_ntfp.FP_RtlInitializeCriticalSectionAndSpinCount = dlsym(_g_ntdll, "RtlInitializeCriticalSectionAndSpinCount");
		_g_ntfp.FP_RtlDeleteCriticalSection = dlsym(_g_ntdll, "RtlDeleteCriticalSection");
		_g_ntfp.FP_RtlEnterCriticalSection = dlsym(_g_ntdll, "RtlEnterCriticalSection");
		_g_ntfp.FP_RtlLeaveCriticalSection = dlsym(_g_ntdll, "RtlLeaveCriticalSection");
		_g_ntfp.FP_RtlTryEnterCriticalSection = dlsym(_g_ntdll, "RtlTryEnterCriticalSection");
		_g_ntfp.FP_RtlpWaitForCriticalSection = dlsym(_g_ntdll, "RtlpWaitForCriticalSection");
		_g_ntfp.FP_RtlpUnWaitCriticalSection = dlsym(_g_ntdll, "RtlpUnWaitCriticalSection");


		/////////////////////
		// Keyed Event Functions
		/////////////////////

		_g_ntfp.FP_NtCreateKeyedEvent = dlsym(_g_ntdll, "NtCreateKeyedEvent");
		_g_ntfp.FP_NtOpenKeyedEvent = dlsym(_g_ntdll, "NtOpenKeyedEvent");
		_g_ntfp.FP_NtWaitForKeyedEvent = dlsym(_g_ntdll, "NtWaitForKeyedEvent");
		_g_ntfp.FP_NtReleaseKeyedEvent = dlsym(_g_ntdll, "NtReleaseKeyedEvent");


		/////////////////////
		// PATH Functions
		/////////////////////

		_g_ntfp.FP_RtlDosPathNameToNtPathName_U = dlsym(_g_ntdll, "RtlDosPathNameToNtPathName_U");


		/////////////////////
		// File Functions
		/////////////////////

		_g_ntfp.FP_NtQueryInformationFile = dlsym(_g_ntdll, "NtQueryInformationFile");
		_g_ntfp.FP_NtSetInformationFile = dlsym(_g_ntdll, "NtSetInformationFile");

		_g_ntfp.FP_NtCreateFile = dlsym(_g_ntdll, "NtCreateFile");
		_g_ntfp.FP_NtOpenFile = dlsym(_g_ntdll, "NtOpenFile");
		_g_ntfp.FP_NtReadFile = dlsym(_g_ntdll, "NtReadFile");
		_g_ntfp.FP_NtWriteFile = dlsym(_g_ntdll, "NtWriteFile");
		_g_ntfp.FP_NtCreateNamedPipeFile = dlsym(_g_ntdll, "NtCreateNamedPipeFile");


		/////////////////////
		// File Control Functions
		/////////////////////

		_g_ntfp.FP_NtDuplicateObject = dlsym(_g_ntdll, "NtDuplicateObject");
		_g_ntfp.FP_NtLockFile = dlsym(_g_ntdll, "NtLockFile");
		_g_ntfp.FP_NtUnlockFile = dlsym(_g_ntdll, "NtUnlockFile");


		/////////////////////
		// FileSystem Functions
		/////////////////////

		_g_ntfp.FP_NtQueryVolumeInformationFile = dlsym(_g_ntdll, "NtQueryVolumeInformationFile");
		_g_ntfp.FP_NtSetVolumeInformationFile = dlsym(_g_ntdll, "NtSetVolumeInformationFile");


		/////////////////////
		// Time Functions
		/////////////////////

		_g_ntfp.FP_NtGetTickCount = dlsym(_g_ntdll, "NtGetTickCount");

	}
	return &_g_ntfp;
}

#ifndef _MSC_VER

/************************************************************************/
/* provide the APIs for "libc/upstream-dlmalloc/malloc.c"               */
/* without "kernel32.dll" on MINGW-Builds                               */
/************************************************************************/

void
WINAPI
_imp__InitializeCriticalSection (
	__out  LPCRITICAL_SECTION lpCriticalSection
) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlInitializeCriticalSection(lpCriticalSection);
}
BOOL
WINAPI
_imp__InitializeCriticalSectionAndSpinCount (
	__out  LPCRITICAL_SECTION lpCriticalSection,
	__in   DWORD dwSpinCount
) {
	ntsc_t *ntfp = ntdll_getFP();
	return ntfp->FP_RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
}

void
WINAPI
_imp__EnterCriticalSection (
	__inout  LPCRITICAL_SECTION lpCriticalSection
) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlEnterCriticalSection(lpCriticalSection);
}

void
WINAPI
_imp__LeaveCriticalSection (
	__inout  LPCRITICAL_SECTION lpCriticalSection
) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlLeaveCriticalSection(lpCriticalSection);
}

LPVOID
WINAPI
_imp__VirtualAlloc (
	__in_opt  LPVOID lpAddress,
	__in      SIZE_T dwSize,
	__in      DWORD flAllocationType,
	__in      DWORD flProtect
) {
	NTSTATUS ret;
	PVOID vmem = lpAddress;
	SIZE_T vmemLen = dwSize;
	
	ntsc_t *ntfp = ntdll_getFP();
	ret = ntfp->FP_NtAllocateVirtualMemory(XbNtCurrentProcess(), &vmem, 0, &vmemLen, flAllocationType, flProtect);
	if (NT_SUCCESS(ret)) {
		return vmem;
	} else {
		return NULL;
	}
}

BOOL
WINAPI
_imp__VirtualFree (
	__in  LPVOID lpAddress,
	__in  SIZE_T dwSize,
	__in  DWORD dwFreeType
) {
	NTSTATUS ret;
	PVOID vmem = lpAddress;
	SIZE_T vmemLen = dwSize;

	ntsc_t *ntfp = ntdll_getFP();
	ret = ntfp->FP_NtFreeVirtualMemory(XbNtCurrentProcess(), &vmem, &vmemLen, dwFreeType);
	if (NT_SUCCESS(ret)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL
WINAPI
_imp__VirtualProtect (
	__in   LPVOID lpAddress,
	__in   SIZE_T dwSize,
	__in   DWORD flNewProtect,
	__out  PDWORD lpflOldProtect
) {
	NTSTATUS ret;
	PVOID vmem = lpAddress;
	SIZE_T vmemLen = dwSize;

	ntsc_t *ntfp = ntdll_getFP();
	ret = ntfp->FP_NtProtectVirtualMemory(XbNtCurrentProcess(), &vmem, &vmemLen, flNewProtect, lpflOldProtect);
	if (NT_SUCCESS(ret)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

SIZE_T
WINAPI
_imp__VirtualQuery (
	__in_opt  LPCVOID lpAddress,
	__out     PMEMORY_BASIC_INFORMATION lpBuffer,
	__in      SIZE_T dwLength
) {
	NTSTATUS ret;
	ULONG retSize;
	PVOID vmem = (PVOID)lpAddress;

	ntsc_t *ntfp = ntdll_getFP();
	ret = ntfp->FP_NtQueryVirtualMemory(XbNtCurrentProcess(), &vmem, MemoryBasicInformation, lpBuffer, dwLength, &retSize);
	if (NT_SUCCESS(ret)) {
		return retSize;
	} else {
		return 0;
	}
}

#define PV_NT351 0x00030033

static
VOID
WINAPI
xb_GetSystemInfoInternal (
	__in  PSYSTEM_BASIC_INFORMATION BasicInfo,
	__in  PSYSTEM_PROCESSOR_INFORMATION ProcInfo,
	__out LPSYSTEM_INFO SystemInfo
) {
	SystemInfo->wProcessorArchitecture = ProcInfo->ProcessorArchitecture;
	SystemInfo->wReserved = 0;
	SystemInfo->dwPageSize = BasicInfo->PageSize;
	SystemInfo->lpMinimumApplicationAddress = (PVOID)BasicInfo->MinimumUserModeAddress;
	SystemInfo->lpMaximumApplicationAddress = (PVOID)BasicInfo->MaximumUserModeAddress;
	SystemInfo->dwActiveProcessorMask = BasicInfo->ActiveProcessorsAffinityMask;
	SystemInfo->dwNumberOfProcessors = BasicInfo->NumberOfProcessors;
	SystemInfo->wProcessorLevel = ProcInfo->ProcessorLevel;
	SystemInfo->wProcessorRevision = ProcInfo->ProcessorRevision;
	SystemInfo->dwAllocationGranularity = BasicInfo->AllocationGranularity;

	switch (ProcInfo->ProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		switch (ProcInfo->ProcessorLevel) {
		case 3:
			SystemInfo->dwProcessorType = PROCESSOR_INTEL_386;
			break;
		case 4:
			SystemInfo->dwProcessorType = PROCESSOR_INTEL_486;
			break;
		default:
			SystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
		}
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		SystemInfo->dwProcessorType = PROCESSOR_AMD_X8664;
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		SystemInfo->dwProcessorType = PROCESSOR_INTEL_IA64;
		break;
	default:
		SystemInfo->dwProcessorType = 0;
		break;
	}

	//if (PV_NT351 > GetProcessVersion(0)) {
	SystemInfo->wProcessorLevel = 0;
	SystemInfo->wProcessorRevision = 0;
	//}
}

void 
WINAPI
_imp__GetSystemInfo (
	__out  LPSYSTEM_INFO lpSystemInfo
) {
	SYSTEM_BASIC_INFORMATION BasicInfo;
	SYSTEM_PROCESSOR_INFORMATION ProcInfo;
	NTSTATUS Status;

	ntsc_t *ntfp = ntdll_getFP();

	Status = ntfp->FP_NtQuerySystemInformation(SystemBasicInformation,
		&BasicInfo,
		sizeof(BasicInfo),
		0);
	if (!NT_SUCCESS(Status)) return;

	Status = ntfp->FP_NtQuerySystemInformation(SystemProcessorInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		0);
	if (!NT_SUCCESS(Status)) return;

	ntfp->FP_RtlZeroMemory(lpSystemInfo, sizeof (SYSTEM_INFO));
	xb_GetSystemInfoInternal(&BasicInfo, &ProcInfo, lpSystemInfo);
}

DWORD
WINAPI
_imp__GetTickCount(void) {
	ntsc_t *ntfp = ntdll_getFP();
	return ntfp->FP_NtGetTickCount();
}

DWORD
WINAPI
_imp__SleepEx(
	__in  DWORD dwMilliseconds,
	__in  BOOL bAlertable
) {
	LARGE_INTEGER Time;
	PLARGE_INTEGER TimePtr;
	NTSTATUS errCode;
	RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME ActCtx;

	ntsc_t *ntfp = ntdll_getFP();

	/* APCs must execute with the default activation context */
	if (bAlertable)	{
		/* Setup the frame */
		ntfp->FP_RtlZeroMemory(&ActCtx, sizeof(ActCtx));
		ActCtx.Size = sizeof(ActCtx);
		ActCtx.Format = RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER;
		ntfp->FP_RtlActivateActivationContextUnsafeFast(&ActCtx, NULL);
	}

	/* Convert the timeout */
	if (dwMilliseconds == INFINITE) {
		Time.LowPart = 0;
		Time.HighPart = 0x80000000;
		TimePtr = &Time;
	} else {
		Time.QuadPart = dwMilliseconds * -10000;
		TimePtr = &Time;
	}

	/* Loop the delay while APCs are alerting us */
	do {
		/* Do the delay */
		errCode = ntfp->FP_NtDelayExecution((BOOLEAN)bAlertable, TimePtr);
	}
	while ((bAlertable) && (errCode == STATUS_ALERTED));

	/* Cleanup the activation context */
	if (bAlertable) ntfp->FP_RtlDeactivateActivationContextUnsafeFast(&ActCtx);

	/* Return the correct code */
	return (errCode == STATUS_USER_APC) ? STATUS_USER_APC : 0;  // STATUS_USER_APC == WAIT_IO_COMPLETION
}

#endif // !_MSC_VER

