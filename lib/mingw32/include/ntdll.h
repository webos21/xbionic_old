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

#ifndef __NTDLL_H__
#define __NTDLL_H__

//////////////////////////////////////////
// Replacing the Specification Strings
//////////////////////////////////////////
#define __allowed(p) __$allowed_##p
#define __$allowed_as_global_decl            /* empty */
#define __$allowed_on_function_or_typedecl   /* empty */
#define __$allowed_on_typedecl               /* empty */
#define __$allowed_on_return                 /* empty */
#define __$allowed_on_parameter              /* empty */
#define __$allowed_on_function               /* empty */
#define __$allowed_on_struct                 /* empty */
#define __$allowed_on_field                  /* empty */
#define __$allowed_on_parameter_or_return    /* empty */
#define __$allowed_on_global_or_field        /* empty */


//////////////////////////////////////////
// the Specification Strings
//////////////////////////////////////////
#define __in                               __allowed(on_parameter)
#define __in_opt                           __allowed(on_parameter)

#define __out                              __allowed(on_parameter)
#define __out_opt                          __allowed(on_parameter)

#define __inout                            __allowed(on_parameter)

#define __field_bcount_part(size,init)     __allowed(on_field)


//////////////////////////////////////////
// Definition for Declaring Functions
//////////////////////////////////////////
#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif //no-NULL

#define NTSYSAPI
#ifdef _MSC_VER
#define NTAPI
#else
#define NTAPI           __attribute__((__stdcall__))
#endif

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES  0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE   0x00000004 // don't update synchronization objects

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS) 0)
#endif
#define STATUS_PROCESS_CLONED           ((NTSTATUS) 0x00000129)



//////////////////////////////////////////
// Windows Types
//////////////////////////////////////////

#if !defined(_W64)
#if !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300
#define _W64 __w64
#else
#define _W64
#endif
#endif

#if defined(_M_MRX000) && !(defined(MIDL_PASS) || defined(RC_INVOKED)) && defined(ENABLE_RESTRICTED)
#define RESTRICTED_POINTER __restrict
#else
#define RESTRICTED_POINTER
#endif

// Basics
#ifndef VOID
#define VOID               void
typedef char               CHAR;
typedef short              SHORT;
typedef long               LONG;
#if !defined(MIDL_PASS)
typedef int                INT;
#endif
#endif

typedef unsigned char      UCHAR;

typedef int                BOOL;

typedef unsigned short     USHORT;

typedef long               LONG;

// 32-bit, Windows is __LLP64!!
typedef unsigned long      ULONG;

typedef long long          LONGLONG;

typedef void              *PVOID;

typedef unsigned short     WCHAR;
typedef WCHAR             *PWCHAR,*LPWCH,*PWCH;

typedef UCHAR              BOOLEAN;    // winnt
typedef BOOLEAN           *PBOOLEAN;   // winnt

typedef ULONG              LOGICAL;
typedef ULONG             *PLOGICAL;

typedef unsigned short     WORD;
typedef unsigned long      DWORD;
typedef void              *HANDLE;
typedef int                NTSTATUS;

#if defined(_WIN64)
typedef long long           INT_PTR, *PINT_PTR;
typedef unsigned long long  UINT_PTR, *PUINT_PTR;

typedef long long          LONG_PTR, *PLONG_PTR;
typedef unsigned long long ULONG_PTR, *PULONG_PTR;

#define __int3264          __int64

#else
typedef _W64 int           INT_PTR, *PINT_PTR;
typedef _W64 unsigned int  UINT_PTR, *PUINT_PTR;

typedef _W64 long          LONG_PTR, *PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, *PULONG_PTR;

#define __int3264           __int32

#endif

//////////////////////////////////////////
// Structured Types
//////////////////////////////////////////

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    __field_bcount_part(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

typedef struct _CLIENT_ID {
    /* These are numeric ids */
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

#if defined(MIDL_PASS)
typedef struct _LARGE_INTEGER {
#else // MIDL_PASS
typedef union _LARGE_INTEGER {
	struct {
		DWORD LowPart;
		LONG HighPart;
	} DUMMYSTRUCTNAME;
	struct {
		DWORD LowPart;
		LONG HighPart;
	} u;
#endif //MIDL_PASS
	LONGLONG QuadPart;
} LARGE_INTEGER;
typedef LARGE_INTEGER *PLARGE_INTEGER;


//////////////////////////////////////////
// NTDLL Structures
//////////////////////////////////////////

// Pointer to a SECURITY_DESCRIPTOR  opaque data type.
typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;

typedef struct _SECTION_BASIC_INFORMATION {
  ULONG                   Unknown;
  ULONG                   SectionAttributes;
  LARGE_INTEGER           SectionSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
  PVOID                   EntryPoint;
  ULONG                   StackZeroBits;
  ULONG                   StackReserved;
  ULONG                   StackCommit;
  ULONG                   ImageSubsystem;
  WORD                    SubSystemVersionLow;
  WORD                    SubSystemVersionHigh;
  ULONG                   Unknown1;
  ULONG                   ImageCharacteristics;
  ULONG                   ImageMachineType;
  ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG {
  WORD   Type;
  WORD   CreatorBackTraceIndex;
  struct _RTL_CRITICAL_SECTION *CriticalSection;
  LIST_ENTRY ProcessLocksList;
  DWORD EntryCount;
  DWORD ContentionCount;
  DWORD Flags;
  WORD   CreatorBackTraceIndexHigh;
  WORD   SpareWORD  ;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

#pragma pack(push, 8)
typedef struct _RTL_CRITICAL_SECTION {
  PRTL_CRITICAL_SECTION_DEBUG DebugInfo;

  //  The following three fields control entering and exiting the critical
  //  section for the resource

  LONG LockCount;
  LONG RecursionCount;
  HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
  HANDLE LockSemaphore;
  ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#pragma pack(pop)

typedef struct _RTL_SRWLOCK {
  PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;
#define RTL_SRWLOCK_INIT {0}

typedef struct _RTL_CONDITION_VARIABLE {
  PVOID Ptr;
} RTL_CONDITION_VARIABLE, *PRTL_CONDITION_VARIABLE;
#define RTL_CONDITION_VARIABLE_INIT {0}
#define RTL_CONDITION_VARIABLE_LOCKMODE_SHARED  0x1

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG                   Size;
	HANDLE                  ProcessHandle;
	HANDLE                  ThreadHandle;
	CLIENT_ID               ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;



//////////////////////////////////////////
// Structure for NTDLL APIs
//////////////////////////////////////////
typedef struct _st_ntsc {
	NTSYSAPI NTSTATUS NTAPI (*FP_RtlExitUserProcess) (
		__in NTSTATUS ExitStatus
		);
	NTSYSAPI NTSTATUS NTAPI (*FP_RtlExitUserThread) (
		__in NTSTATUS ExitStatus
		);
	NTSYSAPI NTSTATUS NTAPI (*FP_RtlCreateProcessParameters) (
		__out PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
		__in PUNICODE_STRING ImagePathName,
		__in_opt PUNICODE_STRING DllPath,
		__in_opt PUNICODE_STRING CurrentDirectory,
		__in_opt PUNICODE_STRING CommandLine,
		__in_opt PVOID Environment,
		__in_opt PUNICODE_STRING WindowTitle,
		__in_opt PUNICODE_STRING DesktopInfo,
		__in_opt PUNICODE_STRING ShellInfo,
		__in_opt PUNICODE_STRING RuntimeData
		);
	NTSYSAPI NTSTATUS NTAPI (*FP_RtlDestroyProcessParameters) (
		__in PRTL_USER_PROCESS_PARAMETERS *pProcessParameters
		);
	NTSYSAPI NTSTATUS NTAPI (*FP_RtlCreateUserProcess) (
		__in PUNICODE_STRING  ImageFileName,
		__in ULONG  Attributes,
		__inout PRTL_USER_PROCESS_PARAMETERS  ProcessParameters,
		__in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		__in_opt HANDLE ParentProcess,
		__in BOOLEAN  InheritHandles,
		__in_opt HANDLE DebugPort,
		__in_opt HANDLE ExceptionPort,
		__out PRTL_USER_PROCESS_INFORMATION  ProcessInfo
		);

	NTSYSAPI NTSTATUS NTAPI (*FP_RtlCloneUserProcess) (
		__in ULONG ProcessFlags,
		__in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		__in_opt HANDLE DebugPort,
		__out PRTL_USER_PROCESS_INFORMATION ProcessInformation
		);

	NTSYSAPI VOID NTAPI (*FP_RtlUpdateClonedCriticalSection) (
		__inout PRTL_CRITICAL_SECTION CriticalSection
		);

	NTSYSAPI VOID NTAPI (*FP_RtlUpdateClonedSRWLock) (
		__inout PRTL_SRWLOCK SRWLock,
		__in LOGICAL Shared // TRUE to set to shared acquire
		);
} ntsc_t;


//////////////////////////////////////////
// Function for getting structure-pointer
//////////////////////////////////////////
ntsc_t *ntdll_getFP();

#endif // __NTDLL_H__
