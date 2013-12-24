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

#include "nttypes.h"

//////////////////////////////////////////
// NTDLL MACRO
//////////////////////////////////////////

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES  0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE   0x00000004 // don't update synchronization objects


//////////////
// AccessMask
//////////////
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_ALL_ACCESS                 (0x001FFFFF)

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

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _PROCESS_BASIC_INFORMATION {
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

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;	
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _THREAD_INFORMATION_CLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	hreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

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

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID                   BaseAddress;
	PVOID                   AllocationBase;
	ULONG                   AllocationProtect;
	ULONG                   RegionSize;
	ULONG                   State;
	ULONG                   Protect;
	ULONG                   Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

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


typedef struct _NT_TIB {
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
	union {
		PVOID FiberData;
		DWORD Version;
	};
#else
	PVOID FiberData;
#endif
	PVOID ArbitraryUserPointer;
	struct _NT_TIB *Self;
} NT_TIB;
typedef NT_TIB *PNT_TIB;

typedef struct _ACTIVATION_CONTEXT_STACK {
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	PVOID ActiveFrame;
	LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	HDC hdc;
	ULONG buffer[310];
} GDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	char* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME;

typedef struct _PROCESSOR_NUMBER {
	WORD   Group;
	BYTE  Number;
	BYTE  Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

// Win7, 7 SP1 layout
typedef struct _TEB_7{
	NT_TIB					NtTib;
	PVOID                   EnvironmentPointer;
	CLIENT_ID               Cid;
	PVOID                   ActiveRpcInfo;
	PVOID                   ThreadLocalStoragePointer;
	PPEB_VISTA_7            Peb;
	ULONG                   LastErrorValue;
	ULONG                   CountOfOwnedCriticalSections;
	PVOID                   CsrClientThread;
	PVOID                   Win32ThreadInfo;
	ULONG                   User32Reserved[0x1a];
	ULONG                   UserReserved[0x5];
	PVOID                   WOW32Reserved;
	ULONG                   CurrentLocale;
	ULONG                   FpSoftwareStatusRegister;
	PVOID                   SystemReserved1[0x36];
	ULONG                   ExceptionCode;
	ACTIVATION_CONTEXT_STACK* ActivationContextStack;
#ifdef _WIN64
	BYTE                    SpareBytes1[0x18];
#else
	BYTE                    SpareBytes1[0x24];
#endif
	ULONG					TxFsContext;
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID               RealClientId;
	HANDLE					GdiCachedProcessHandle;
	ULONG					GdiClientPID;
	ULONG					GdiClientTID;
	PVOID                   GdiThreadLocaleInfo;
	UINT_PTR                Win32ClientInfo[0x3e];
	PVOID                   GlDispatchTable[0xe9];	
	UINT_PTR                GlReserved1[0x1d];
	PVOID                   GlReserved2;
	PVOID                   GlSectionInfo;
	PVOID                   GlSection;
	PVOID                   GlTable;
	PVOID                   GlCurrentRC;
	PVOID                   GlContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING          StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[0x105];
	PVOID                   DeallocationStack;
	PVOID                   TlsSlots[0x40];
	LIST_ENTRY              TlsLinks;
	PVOID                   Vdm;
	PVOID                   ReservedForNtRpc;
	PVOID                   DbgSsReserved[0x2];
	ULONG                   HardErrorsAreDisabled;
#ifdef _WIN64
	PVOID                   Instrumentation[0xB];
#else
	PVOID                   Instrumentation[0x9];
#endif
	GUID                    ActivityId;
	PVOID                   EtwLocalData;
	PVOID                   EtwTraceData;
	PVOID					WinSockData;
	union
	{
		ULONG               GdiBatchCount;
		struct _TEB_7*		pTeb64;
	};
#include <pshpack1.h>
	union
	{
		PROCESSOR_NUMBER        CurrentIdealProcessor;
		ULONG                   IdealProcessorValue;
		struct
		{
			BOOLEAN                 ReservedPad0;
			BOOLEAN                 ReservedPad1;
			BOOLEAN                 ReservedPad2;
			BOOLEAN                 IdealProcessor;
		};
	};
#include <poppack.h>
	ULONG                   GuaranteedStackBytes;
	PVOID                   ReservedForPerf;
	PVOID                   ReservedForOle;
	ULONG                   WaitingOnLoaderLock;
	PVOID                   SavedPriorityState;
	ULONG_PTR				SoftPatchPtr1;
	PVOID					ThreadPoolData;
	PVOID*                  TlsExpansionSlots;
	ULONG                   MuiGeneration;
	ULONG                   IsImpersonating;
	PVOID                   NlsCache;
	PVOID                   pShimData;
	ULONG                   HeapVirtualAffinity;
	HANDLE                  CurrentTransactionHandle;
	TEB_ACTIVE_FRAME*       ActiveFrame;
	PVOID					FlsData;
	PVOID					PreferredLanguages;
	PVOID					UserPrefLanguages;
	PVOID					MergedPrefLanguages;
	ULONG					MuiImpersonation;
#include <pshpack1.h>
	union
	{
		volatile USHORT		CrossTebFlags;
		USHORT				SpareCrossTebBits: 0x10;
	};
	union
	{
		USHORT				SameTebFlags;
		struct
		{
			USHORT          SafeThunkCall: 1;
			USHORT          InDbgPrint: 1;
			USHORT          HasFiberData: 1;
			USHORT          SkipThreadAttach: 1;
			USHORT          WerInShipAssertCode: 1;
			USHORT          RanProcessInit: 1;
			USHORT          ClonedThread: 1;
			USHORT          SuppressDebugMsg: 1;
			USHORT          DisableUserStackWalk: 1;
			USHORT          RtlExceptionAttached: 1;
			USHORT          InitialThread: 1;
			USHORT          SpareSameTebBits: 5;
		};
	};
#include <poppack.h>
	BOOLEAN                 FreeStackOnTermination;
	ULONG                   ImpersonationLocale;
	PVOID					TxnScopeEnterCallback;
	PVOID					TxnScopeExitCallback;
	PVOID					TxnScopeContext;
	ULONG					LockCount;
	ULONG					SpareUlong0;
	PVOID					ResourceRetValue;
} TEB_7, *PTEB_7;



//////////////////////////////////////////
// Structure for NTDLL APIs
//////////////////////////////////////////

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
	// Error Functions
	/////////////////////

	NTSYSAPI_N DWORD (NTAPI *FP_RtlGetLastWin32Error) (void);
	
	NTSYSAPI_N void (NTAPI *FP_RtlSetLastWin32Error) (
		DWORD err
		);


	/////////////////////
	// ProcMon(Stack Trace) Functions
	/////////////////////


	/////////////////////
	// CloseHandle Functions : NtOpenProcess / NtOpenThread
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtClose) (
		__in      HANDLE Handle
		);


	/////////////////////
	// Memory Functions
	/////////////////////

	NTSYSAPI_N PVOID (NTAPI *FP_RtlAllocateHeap) (
		__in      PVOID HeapHandle,
		__in_opt  ULONG Flags,
		__in      SIZE_T Size
		);

	NTSYSAPI_N PVOID (NTAPI *FP_RtlReAllocateHeap) (
		__in      PVOID HeapHandle,
		__in_opt  ULONG Flags,
		__in      PVOID MemoryPointer,
		__in      SIZE_T Size
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlFreeHeap) (
		__in      PVOID HeapHandle,
		__in_opt  ULONG Flags,
		__in      PVOID HeapBase
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlZeroMemory) (
		__out  PVOID Destination,
		__in   SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlFillMemory) (
		__out  PVOID Destination,
		__in   SIZE_T Length,
		__in   UCHAR Fill
		);

	NTSYSAPI_N SIZE_T (NTAPI *FP_RtlCompareMemory) (
		__in  const VOID *Source1,
		__in  const VOID *Source2,
		__in  SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlCopyMemory) (
		__out  PVOID Destination,
		__in   const PVOID Source,
		__in   SIZE_T Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlMoveMemory) (
		__out  PVOID Destination,
		__in   const PVOID Source,
		__in   SIZE_T Length
		);


	/////////////////////
	// Virtual Memory Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtAllocateVirtualMemory) (
		__in     HANDLE     ProcessHandle,
		__inout  PVOID     *BaseAddress,
		__in     ULONG_PTR  ZeroBits,
		__inout  PSIZE_T    RegionSize,
		__in     ULONG      AllocationType,
		__in     ULONG      Protect
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtFlushVirtualMemory) (
		__in     HANDLE            ProcessHandle,
		__inout  PVOID            *BaseAddress,
		__inout  PSIZE_T           RegionSize,
		__out    PIO_STATUS_BLOCK  IoStatus
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtFreeVirtualMemory) (
		__in     HANDLE   ProcessHandle,
		__inout  PVOID   *BaseAddress,
		__inout  PSIZE_T  RegionSize,
		__in     ULONG    FreeType
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtLockVirtualMemory) (
		__in    HANDLE    ProcessHandle,
		__in    PVOID    *BaseAddress,
		__inout PULONG    NumberOfBytesToLock,
		__in    ULONG     LockOption
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtProtectVirtualMemory) (
		__in    HANDLE    ProcessHandle,
		__inout PVOID    *BaseAddress,
		__inout PULONG    NumberOfBytesToProtect,
		__in    ULONG     NewAccessProtection,
		__out   PULONG    OldAccessProtection
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryVirtualMemory) (
		__in      HANDLE                   ProcessHandle,
		__in      PVOID                    BaseAddress,
		__in      MEMORY_INFORMATION_CLASS MemoryInformationClass,
		__out     PVOID                    Buffer,
		__in      ULONG                    Length,
		__out_opt PULONG                   ResultLength
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtReadVirtualMemory) (
		__in      HANDLE    ProcessHandle,
		__in      PVOID     BaseAddress,
		__out     PVOID     Buffer,
		__in      ULONG     NumberOfBytesToRead,
		__out_opt PULONG    NumberOfBytesReaded
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtUnlockVirtualMemory) (
		__in    HANDLE      ProcessHandle,
		__in    PVOID      *BaseAddress,
		__inout PULONG      NumberOfBytesToUnlock,
		__in    ULONG       LockType
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtWriteVirtualMemory) (
		__in      HANDLE    ProcessHandle,
		__in      PVOID     BaseAddress,
		__in      PVOID     Buffer,
		__in      ULONG     NumberOfBytesToWrite,
		__out_opt PULONG    NumberOfBytesWritten
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

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCreateUnicodeStringFromAsciiz) (
		__out PUNICODE_STRING  Destination,  
		__in  PCSZ  Source  
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

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendAsciizToString) (
		__inout PSTRING  Destination,  
		__in    PCSZ  Source  
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendStringToString) (
		__inout  PSTRING Destination,
		__in     const STRING *Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendUnicodeStringToString) (
		__inout  PUNICODE_STRING Destination,
		__in     PCUNICODE_STRING Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendUnicodeToString) (
		__inout   PUNICODE_STRING Destination,
		__in_opt  PCWSTR Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlMultiAppendUnicodeStringBuffer) ( 
		__inout PRTL_UNICODE_STRING_BUFFER pStrBuffer, 
		__in ULONG numAddends, 
		__in PCUNICODE_STRING pAddends 
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

	NTSYSAPI_N WCHAR (NTAPI *FP_RtlDowncaseUnicodeChar) (
		__in  WCHAR SourceCharacter
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDowncaseUnicodeString) (
		__inout PUNICODE_STRING DestinationString,
		__in    PCUNICODE_STRING SourceString,
		__in    BOOLEAN AllocateDestinationString
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

	
	/////////////////////
	// Environment Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCreateEnvironment) (
		__in      BOOLEAN   Inherit,
		__out     PVOID    *Environment
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlDestroyEnvironment) (
		__in      PVOID     Environment
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExpandEnvironmentStrings_U) (
		__in_opt   PVOID               Environment,
		__in       PUNICODE_STRING     SourceString,
		__out      PUNICODE_STRING     DestinationString,
		__out_opt  PULONG              DestinationBufferLength
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlQueryEnvironmentVariable_U) (
		__in_opt   PVOID               Environment,
		__in       PUNICODE_STRING     VariableName,
		__out      PUNICODE_STRING     VariableValue
		);
		
	NTSYSAPI_N VOID (NTAPI *FP_RtlSetCurrentEnvironment) (
		__in      PVOID                NewEnvironment,
		__out_opt PVOID               *OldEnvironment
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlSetEnvironmentStrings) (
		__in      PWCHAR               NewEnvironment,
		__in      ULONG                NewEnvironmentSize
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlSetEnvironmentVariable) (
		__inout_opt PVOID             *Environment,
		__in        PUNICODE_STRING    VariableName,
		__in        PUNICODE_STRING    VariableValue
		);


	/////////////////////
	// Process Functions
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
		__in PRTL_USER_PROCESS_PARAMETERS pProcessParameters
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

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExitUserProcess) (
		__in NTSTATUS ExitStatus
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtWaitForSingleObject) (
		__in  HANDLE Handle,
		__in  BOOLEAN Alertable,
		__in  PLARGE_INTEGER Timeout
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtOpenProcess) (
		__out     PHANDLE ProcessHandle,
		__in      ACCESS_MASK DesiredAccess,
		__in      POBJECT_ATTRIBUTES ObjectAttributes,
		__in_opt  PCLIENT_ID ClientId
		);


	/////////////////////
	// Thread Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCreateUserThread) (
		__in     HANDLE               ProcessHandle,
		__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
		__in     BOOLEAN              CreateSuspended,
		__in     ULONG                StackZeroBits,
		__inout  PULONG               StackReserved,
		__inout  PULONG               StackCommit,
		__in     PVOID                StartAddress,
		__in_opt PVOID                StartParameter,
		__out    PHANDLE              ThreadHandle,
		__out    PCLIENT_ID           ClientID
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExitUserThread) (
		__in NTSTATUS ExitStatus
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtDelayExecution) (
		__in BOOLEAN              Alertable,
		__in PLARGE_INTEGER       DelayInterval // 100-us
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtSuspendThread) (
		__in      HANDLE          ThreadHandle,
		__out_opt PULONG          PreviousSuspendCount
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtResumeThread) (
		__in      HANDLE          ThreadHandle,
		__out_opt PULONG          SuspendCount
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtOpenThread) (
		__out  PHANDLE             ThreadHandle,
		__in   ACCESS_MASK         DesiredAccess,
		__in   POBJECT_ATTRIBUTES  ObjectAttributes,
		__in   PCLIENT_ID          ClientId
		);
	
	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryInformationThread) (
		__in       HANDLE                    ThreadHandle,
		__in       THREAD_INFORMATION_CLASS  ThreadInformationClass,
		__inout    PVOID                     ThreadInformation,
		__in       ULONG                     ThreadInformationLength,
		__out_opt  PULONG                    ReturnLength
		);


	/////////////////////
	// PATH Functions
	/////////////////////

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlDosPathNameToNtPathName_U) (
		__in PCWSTR DosName,
		__out PUNICODE_STRING NtName,
		__out_opt PCWSTR* DosFilePath,
		__out_opt PUNICODE_STRING NtFilePath
		);

} ntsc_t;

//////////////////////////////////////////
// Macro for NTDLL APIs
//////////////////////////////////////////

#define XbNtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define XbNtCurrentThread()  ( (HANDLE)(LONG_PTR) -2 )
#define XbZwCurrentProcess() XbNtCurrentProcess()
#define XbZwCurrentThread()  XbNtCurrentThread()

/* FIXME? Windows NT's ntdll doesn't export RtlGetProcessHeap() */
//#define RtlGetProcessHeap() ((HANDLE)NtCurrentPeb()->ProcessHeap)
#define XbRtlGetProcessHeap(pFP) ((HANDLE)((pFP)->FP_RtlGetCurrentPeb()->ProcessHeap))

#ifdef _MSC_VER
#ifdef _WIN64
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
DWORD64 Xb__readgsqword (__in DWORD Offset);
__forceinline PTEB_7 XbNtCurrentTeb(void) {
	return (PTEB_7)Xb__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}
#else  // !_WIN64
#define PcTeb 0x18
__forceinline PTEB_7 XbNtCurrentTeb(void) {
	__asm mov eax, fs:[PcTeb]
}
#endif // _WIN64
#else  // !_MSC_VER
#ifdef _WIN64
#define PcTeb 0x30
inline __attribute__((always_inline)) static PTEB_7 XbNtCurrentTeb(void) {
	PTEB_7 _teb = NULL;
	__asm__ __volatile__("movl %%fs:$PcTeb, %k[_teb]" : [_teb] "=r" (_teb));
	return _teb;
}
#else  // !_WIN64
#define PcTeb 0x18
inline __attribute__((always_inline)) static PTEB_7 XbNtCurrentTeb(void) {
	PTEB_7 _teb = NULL;
	__asm__ __volatile__("movl %%fs:$PcTeb, %k[_teb]" : [_teb] "=r" (_teb));
	return _teb;
}
#endif // _WIN64
#endif // _MSC_VER


//////////////////////////////////////////
// Function for getting structure-pointer
//////////////////////////////////////////
ntsc_t *ntdll_getFP();

#endif // __NTDLL_H__
