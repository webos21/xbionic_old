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

#ifdef _WINNT_
#pragma warning(push)
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(pop)
#else
#include <ntstatus.h>
#endif

#ifndef __ATTR_SAL
//////////////////////////////////////////
// Replacing the Specification Strings
//////////////////////////////////////////
#define __allowed(p)                       __$allowed_##p
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
#endif // __ATTR_SAL

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

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef CONST
#define CONST const
#endif


// NTSYSAPI(dllimport) is not required!!
//#define NTSYSAPI
#define NTSYSAPI_N

#ifndef NTAPI
#ifdef _MSC_VER
#define NTAPI           __stdcall
#else
#define NTAPI           __attribute__((__stdcall__))
#endif
#endif //NTAPI

#define INVALID_HANDLE_VALUE                     ((HANDLE)(LONG_PTR)-1)
#define INVALID_FILE_SIZE                        ((DWORD)0xFFFFFFFF)
#define INVALID_SET_FILE_POINTER                 ((DWORD)-1)
#define INVALID_FILE_ATTRIBUTES                  ((DWORD)-1)

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES  0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE   0x00000004 // don't update synchronization objects

#define HANDLE_FLAG_INHERIT                      0x00000001
#define HANDLE_FLAG_PROTECT_FROM_CLOSE           0x00000002

#define NT_SUCCESS(Status)                       (((NTSTATUS)(Status)) >= 0)


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

#ifndef BASETYPES
#define BASETYPES
typedef unsigned long      ULONG;
typedef ULONG             *PULONG;
typedef unsigned short     USHORT;
typedef USHORT            *PUSHORT;
typedef unsigned char      UCHAR;
typedef UCHAR             *PUCHAR;
typedef char              *PSZ;
#endif  /* !BASETYPES */

typedef int                BOOL;

typedef long long          LONGLONG;
typedef unsigned long long ULONGLONG;

typedef VOID              *PVOID;
typedef VOID              *LPVOID;

typedef unsigned short     WCHAR;
typedef WCHAR             *PWCHAR,*LPWCH,*PWCH;

typedef UCHAR              BOOLEAN;    // winnt
typedef BOOLEAN           *PBOOLEAN;   // winnt

typedef ULONG              LOGICAL;
typedef ULONG             *PLOGICAL;

typedef unsigned char      BYTE;
typedef unsigned short     WORD;
typedef unsigned long      DWORD;
typedef void              *HANDLE;

#ifdef _WINDOWS_
#pragma warning(push)
#pragma warning(disable:4142)
typedef int                NTSTATUS;
#pragma warning(pop)
#else
typedef int                NTSTATUS;
#endif

typedef DWORD              ACCESS_MASK;
typedef ACCESS_MASK       *PACCESS_MASK;


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


typedef ULONG_PTR          DWORD_PTR, *PDWORD_PTR;

typedef ULONG_PTR          SIZE_T, *PSIZE_T;


typedef CHAR              *NPSTR, *LPSTR, *PSTR;
typedef CONST char        *PCSZ;
typedef CONST WCHAR       *LPCWSTR, *PCWSTR;
typedef CHAR              *PCHAR, *LPCH, *PCH;
typedef CONST CHAR        *LPCSTR, *PCSTR;


//////////////////////////////////////////
// Structured Types
//////////////////////////////////////////

typedef struct _ANSI_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PSTR    Buffer;
} ANSI_STRING, STRING, *PSTRING;
typedef ANSI_STRING *PANSI_STRING;
typedef const ANSI_STRING *PCANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT   Length;
	USHORT   MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    __field_bcount_part(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

#ifndef _WINNT_
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY       *Flink;
	struct _LIST_ENTRY       *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
typedef struct _RTL_CRITICAL_SECTION_DEBUG {
	WORD                      Type;
	WORD                      CreatorBackTraceIndex;
	struct _RTL_CRITICAL_SECTION *CriticalSection;
	LIST_ENTRY                ProcessLocksList;
	DWORD                     EntryCount;
	DWORD                     ContentionCount;
	DWORD                     Flags;
	WORD                      CreatorBackTraceIndexHigh;
	WORD                      SpareWORD;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

#pragma pack(push, 8)
typedef struct _RTL_CRITICAL_SECTION {
	PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
	//  The following three fields control entering and exiting the critical
	//  section for the resource
	LONG                      LockCount;
	LONG                      RecursionCount;
	HANDLE                    OwningThread;     // from the thread's ClientId->UniqueThread
	HANDLE                    LockSemaphore;
	ULONG_PTR                 SpinCount;        // force size on 64-bit systems when packed
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#pragma pack(pop)

typedef struct _RTL_SRWLOCK {
	PVOID                     Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;
#define RTL_SRWLOCK_INIT {0}

typedef struct _RTL_CONDITION_VARIABLE {
	PVOID                     Ptr;
} RTL_CONDITION_VARIABLE, *PRTL_CONDITION_VARIABLE;
#define RTL_CONDITION_VARIABLE_INIT {0}
#define RTL_CONDITION_VARIABLE_LOCKMODE_SHARED  0x1

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

#if defined(MIDL_PASS)
typedef struct _ULARGE_INTEGER {
#else // MIDL_PASS
typedef union _ULARGE_INTEGER {
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} DUMMYSTRUCTNAME;
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} u;
#endif //MIDL_PASS
	ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef ULARGE_INTEGER *PULARGE_INTEGER;

#endif // _WINNT_

#ifndef _WINBASE_
typedef struct _SECURITY_ATTRIBUTES {
	DWORD                     nLength;
	LPVOID                    lpSecurityDescriptor;
	BOOL                      bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
#endif //_WINBASE_

#ifndef _WINDEF_
typedef struct _HKEY {
	int                       unused;
} HKEY, *PHKEY;
#endif


//////////////////////////////////////////
// NTDLL Structures
//////////////////////////////////////////

// Pointer to a SECURITY_DESCRIPTOR  opaque data type.
typedef PVOID                 PSECURITY_DESCRIPTOR;

typedef RTL_CRITICAL_SECTION  CRITICAL_SECTION;  // winbase.h
typedef PRTL_CRITICAL_SECTION PCRITICAL_SECTION; // winbase.h

typedef ULONG_PTR             KAFFINITY;         // basetsd.h
typedef KAFFINITY            *PKAFFINITY;        // basetsd.h

typedef struct _CLIENT_ID {
	/* These are numeric ids */
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _SECTION_BASIC_INFORMATION {
  ULONG                     BaseAddress;
  ULONG                     SectionAttributes;
  LARGE_INTEGER             SectionSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
  PVOID                     TransferAddress;
  ULONG                     StackZeroBits;
  ULONG                     StackReserved;
  ULONG                     StackCommit;
  ULONG                     ImageSubsystem;
  union {
    struct {
      USHORT                SubSystemMinorVersion;
      USHORT                SubSystemMajorVersion;
    };
    ULONG                   SubSystemVersion;
  };
  ULONG                     GpValue;
  USHORT                    ImageCharacteristics;
  USHORT                    DllCharacteristics;
  USHORT                    Machine;
  BOOLEAN                   ImageContainsCode;
  union {
    UCHAR                   ImageFlags; 
	struct {
      UCHAR                 ComPlusNativeReady: 1;
      UCHAR                 ComPlusILOnly: 1;
      UCHAR                 ImageDynamicallyRelocated: 1;
      UCHAR                 ImageMappedFlat: 1;
      UCHAR                 BaseBelow4gb: 1;
      UCHAR                 Reserved: 3;
	  };
  };   
  ULONG                     LoaderFlags;
  ULONG                     ImageFileSize;
  ULONG                     CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
  DWORD_PTR                 ExitStatus;
  PVOID                     PebBaseAddress;
  DWORD_PTR                 AffinityMask;
  DWORD_PTR                 BasePriority;
  ULONG_PTR                 UniqueProcessId;
  ULONG_PTR                 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
  ProcessBasicInformation = 0,
  ProcessDebugPort = 7,
  ProcessWow64Information = 26,
  ProcessImageFileName = 27,
  ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                    Flags;
  USHORT                    Length;
  ULONG                     TimeStamp;
  UNICODE_STRING            DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
	UNICODE_STRING          DosPath;
	HANDLE                  Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                     MaximumLength;
  ULONG                     Length;
  ULONG                     Flags;
  ULONG                     DebugFlags;
  PVOID                     ConsoleHandle;
  ULONG                     ConsoleFlags;
  HANDLE                    StdInputHandle;
  HANDLE                    StdOutputHandle;
  HANDLE                    StdErrorHandle;
  UNICODE_STRING            CurrentDirectoryPath;
  HANDLE                    CurrentDirectoryHandle;
  UNICODE_STRING            DllPath;
  UNICODE_STRING            ImagePathName;
  UNICODE_STRING            CommandLine;
  PVOID                     Environment;
  ULONG                     StartingPositionLeft;
  ULONG                     StartingPositionTop;
  ULONG                     Width;
  ULONG                     Height;
  ULONG                     CharWidth;
  ULONG                     CharHeight;
  ULONG                     ConsoleTextAttributes;
  ULONG                     WindowFlags;
  ULONG                     ShowWindowFlags;
  UNICODE_STRING            WindowTitle;
  UNICODE_STRING            DesktopName;
  UNICODE_STRING            ShellInfo;
  UNICODE_STRING            RuntimeData;
  RTL_DRIVE_LETTER_CURDIR   DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
  ULONG                     Size;
  HANDLE                    ProcessHandle;
  HANDLE                    ThreadHandle;
  CLIENT_ID                 ClientId;
  SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation_, // avoid the conflict with winnt.h
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE {
  ULONG                     ProcessId;
  BYTE                      ObjectTypeNumber;
  BYTE                      Flags;
  USHORT                    Handle;
  PVOID                     Object;
  ACCESS_MASK               GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG                     HandleCount; /* Or NumberOfHandles if you prefer. */
  SYSTEM_HANDLE             Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _PEB_LDR_DATA_VISTA_7 {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   EntryInProgress;
	BOOLEAN                 ShutdownInProgress;
	PVOID                   ShutdownThread;
} PEB_LDR_DATA_VISTA_7, *PPEB_LDR_DATA_VISTA_7;

typedef struct _RTL_USER_PROCESS_PARAMETERS_VISTA {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	CURDIR                  CurrentDirectoryPath;
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
	volatile ULONG_PTR      EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS_VISTA, *PRTL_USER_PROCESS_PARAMETERS_VISTA, *PPROCESS_PARAMETERS_VISTA;

// Win Vista SP1 / SP2 / Win 7 / Win 7 SP1 version
typedef struct _PEB_VISTA_7 {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
#include <pshpack1.h>
	union {
		BOOLEAN BitField;
		struct {
			BOOLEAN ImageUsesLargePages :1;
			BOOLEAN IsProtectedProcess :1;
			BOOLEAN IsLegacyProcess :1;
			BOOLEAN IsImageDynamicallyRelocated :1;
			BOOLEAN SkipPatchingUser32Forwarders :1;
			BOOLEAN SpareBits :3;
		};
	};
#include <poppack.h>
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_VISTA_7 LoaderData;
	RTL_USER_PROCESS_PARAMETERS_VISTA* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	CRITICAL_SECTION* FastPebLock;
	PVOID AtlThunkSListPtr;
	HKEY IFEOKey;
#include <pshpack1.h>
	union {
		ULONG CrossProcessFlags;
		struct {
			ULONG ProcessInJob :1;
			ULONG ProcessInitializing :1;
			ULONG ProcessUsingVEH :1;
			ULONG ProcessUsingVCH :1;
			ULONG ProcessUsingFTH :1; // 7 Only
			ULONG ReservedBits0 :0x1b;
		};
	};
#include <poppack.h>
	PVOID KernelCallbackTable;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData; 
	PVOID OemCodePageData; 
	PVOID UnicodeCaseTableData; 
	ULONG NumberOfProcessors; 
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps; 
	ULONG MaximumNumberOfHeaps; 
	PVOID* *ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PCRITICAL_SECTION LoaderLock; 
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSPlatformId; 
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
#ifdef _WIN64
	ULONG GdiHandleBuffer[0x3c];
#else
	ULONG GdiHandleBuffer[0x22];
#endif
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[0x20];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	const PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	const PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;
	ULONG_PTR MinimumStackCommit;
	PVOID FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[0x4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr; // Last on Vista
	PVOID pContextData;
	PVOID pImageHeaderHash;
#include <pshpack1.h>
	union {
		ULONG TracingFlags;
		struct {
			ULONG HeapTracingEnable :1;
			ULONG CritSecTracingEnabled :1;
			ULONG SpareTracingBits :0x1e;
		};
	};
#include <poppack.h>
} PEB_VISTA_7, *PPEB_VISTA_7;


//////////////////////////////////////////
// Structure for NTDLL APIs
//////////////////////////////////////////

/* MACROS */
/* FIXME? Windows NT's ntdll doesn't export RtlGetProcessHeap() */
//#define RtlGetProcessHeap() ((HANDLE)NtCurrentPeb()->ProcessHeap)

typedef struct _st_ntsc {

	/////////////////////
	// Process ENV Block
	/////////////////////
	NTSYSAPI_N PPEB_VISTA_7 (NTAPI *FP_RtlGetCurrentPeb)(void);

	/////////////////////
	// Debug Functions
	/////////////////////

	NTSYSAPI_N ULONG (NTAPI *FP_DbgPrint) (
		__in  LPCSTR Format,
		__in  ...
		);


	/////////////////////
	// Exit Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExitUserProcess) (
		__in NTSTATUS ExitStatus
		);

	/////////////////////
	// Thread_Exit Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExitUserThread) (
		__in NTSTATUS ExitStatus
		);


	/////////////////////
	// Fork Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS  (NTAPI *FP_RtlCreateProcessParameters) (
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
	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDestroyProcessParameters) (
		__in PRTL_USER_PROCESS_PARAMETERS *pProcessParameters
		);
	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCreateUserProcess) (
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

	NTSYSAPI_N NTSTATUS (NTAPI *FP_CsrClientCallServer) (
		__inout PVOID Message,
		__inout PVOID Buffer,
		__in ULONG Opcode,
		__in ULONG BufferSize
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryInformationProcess) (
		__in       HANDLE ProcessHandle,
		__in       PROCESSINFOCLASS ProcessInformationClass,
		__out      PVOID ProcessInformation,
		__in       ULONG ProcessInformationLength,
		__out_opt  PULONG ReturnLength
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCloneUserProcess) (
		__in ULONG ProcessFlags,
		__in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		__in_opt HANDLE DebugPort,
		__out PRTL_USER_PROCESS_INFORMATION ProcessInformation
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlUpdateClonedCriticalSection) (
		__inout PRTL_CRITICAL_SECTION CriticalSection
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlUpdateClonedSRWLock) (
		__inout PRTL_SRWLOCK SRWLock,
		__in LOGICAL Shared // TRUE to set to shared acquire
		);

	/////////////////////
	// Memory Functions
	/////////////////////

	NTSYSAPI_N PVOID (NTAPI *FP_RtlAllocateHeap)(
		__in      PVOID HeapHandle,
		__in_opt  ULONG Flags,
		__in      SIZE_T Size
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlFreeHeap)(
		__in      PVOID HeapHandle,
		__in_opt  ULONG Flags,
		__in      PVOID HeapBase
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlZeroMemory)(
		__out  PVOID Destination,
		__in   SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlFillMemory)(
		__out  PVOID Destination,
		__in   SIZE_T Length,
		__in   UCHAR Fill
		);

	NTSYSAPI_N SIZE_T (NTAPI *FP_RtlCompareMemory)(
		__in  const VOID *Source1,
		__in  const VOID *Source2,
		__in  SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlCopyMemory)(
		__out  PVOID Destination,
		__in   const PVOID Source,
		__in   SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlMoveMemory)(
		__out  PVOID Destination,
		__in   const PVOID Source,
		__in   SIZE_T Length
		);

	/////////////////////
	// String Functions
	/////////////////////

	NTSYSAPI_N VOID (NTAPI *FP_RtlInitString) (
		__inout  PSTRING DestinationString,
		__in     PCSZ SourceString
		);

	// Same as RtlInitAnsiString
	//NTSYSAPI_N VOID (NTAPI *FP_RtlInitAnsiString) (
	//	__out     PANSI_STRING DestinationString,
	//	__in_opt  PCSZ SourceString
	//	);

	// Obsolete : Use  RtlUnicodeStringInit
	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlInitUnicodeString) (
		__out  PUNICODE_STRING DestinationString,
		__in   PCWSTR SourceString
		);

	NTSYSAPI_N ULONG (NTAPI *FP_RtlAnsiStringToUnicodeSize) (
		 __in  PANSI_STRING AnsiString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAnsiStringToUnicodeString) (
		__inout  PUNICODE_STRING DestinationString,
		__in     PCANSI_STRING SourceString,
		__in     BOOLEAN AllocateDestinationString
		);

	NTSYSAPI_N ULONG (NTAPI *FP_RtlUnicodeStringToAnsiSize) (
		__in  PUNICODE_STRING UnicodeString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlUnicodeStringToAnsiString) (
		__inout  PANSI_STRING DestinationString,
		__in     PCUNICODE_STRING SourceString,
		__in     BOOLEAN AllocateDestinationString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCopyString) (
		__out     PSTRING DestinationString,
		__in_opt  const STRING *SourceString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCopyUnicodeString) (
		__out     PUNICODE_STRING DestinationString,
		__in_opt  PCUNICODE_STRING SourceString
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlEqualString) (
		__in  const STRING *String1,
		__in  const STRING *String2,
		__in  BOOLEAN CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlEqualUnicodeString) (
		__in  PCUNICODE_STRING String1,
		__in  PCUNICODE_STRING String2,
		__in  BOOLEAN CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCompareString) (
		__in  const STRING *String1,
		__in  const STRING *String2,
		__in  BOOLEAN CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCompareUnicodeString) (
		__in  PCUNICODE_STRING String1,
		__in  PCUNICODE_STRING String2,
		__in  BOOLEAN CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlUpperString) (
		__inout  PSTRING DestinationString,
		__in     const STRING *SourceString
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlUpcaseUnicodeString) (
		__inout  PUNICODE_STRING DestinationString,
		__in     PCUNICODE_STRING SourceString,
		__in     BOOLEAN AllocateDestinationString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlIntegerToChar) (
		__in      ULONG  value,  
		__in_opt  ULONG  base,  
		__in      ULONG  length,  
		__inout   PCHAR  str
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlIntegerToUnicodeString) (
		__in      ULONG Value,
		__in_opt  ULONG Base,
		__inout   PUNICODE_STRING String
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCharToInteger) (
		__in      PCSZ String,
		__in_opt  ULONG Base,
		__out     PULONG Value
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlUnicodeStringToInteger) (
		__in      PCUNICODE_STRING String,
		__in_opt  ULONG Base,
		__out     PULONG Value
		);

	NTSYSAPI_N VOID  (NTAPI *FP_RtlFreeAnsiString) (
		__inout  PANSI_STRING UnicodeString
		);

	NTSYSAPI_N VOID  (NTAPI *FP_RtlFreeUnicodeString) (
		__inout  PUNICODE_STRING UnicodeString
		);

} ntsc_t;

#define DRtlGetProcessHeap(pFP) ((HANDLE)((pFP)->FP_RtlGetCurrentPeb()->ProcessHeap))


//////////////////////////////////////////
// Function for getting structure-pointer
//////////////////////////////////////////
ntsc_t *ntdll_getFP();

#endif // __NTDLL_H__
