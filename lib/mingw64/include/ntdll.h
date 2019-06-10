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
#include "ntimage.h"

//////////////////////////////////////////
// NTDLL MACRO
//////////////////////////////////////////

//////////////
// RtlClone
//////////////
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES  0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE   0x00000004 // don't update synchronization objects


//////////////
// Device Type
//////////////
#define DEVICE_TYPE ULONG


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
#ifndef _WINNT_
#define PROCESS_ALL_ACCESS                 (0x001FFFFF)
#endif // _WINNT_


//////////////
// File Operation
//////////////

#ifndef _WINTERNL_

//
// Valid values for the Attributes field
//

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#endif

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

#endif // _WINTERNL_


#ifndef _WINNT_

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
	FILE_READ_DATA           |\
	FILE_READ_ATTRIBUTES     |\
	FILE_READ_EA             |\
	SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
	FILE_WRITE_DATA          |\
	FILE_WRITE_ATTRIBUTES    |\
	FILE_WRITE_EA            |\
	FILE_APPEND_DATA         |\
	SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
	FILE_READ_ATTRIBUTES     |\
	FILE_EXECUTE             |\
	SYNCHRONIZE)

#define FILE_SHARE_READ                     0x00000001  
#define FILE_SHARE_WRITE                    0x00000002  
#define FILE_SHARE_DELETE                   0x00000004  
#define FILE_ATTRIBUTE_READONLY             0x00000001  
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  
#define FILE_ATTRIBUTE_DEVICE               0x00000040  
#define FILE_ATTRIBUTE_NORMAL               0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  
#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000  
#define FILE_NOTIFY_CHANGE_FILE_NAME        0x00000001   
#define FILE_NOTIFY_CHANGE_DIR_NAME         0x00000002   
#define FILE_NOTIFY_CHANGE_ATTRIBUTES       0x00000004   
#define FILE_NOTIFY_CHANGE_SIZE             0x00000008   
#define FILE_NOTIFY_CHANGE_LAST_WRITE       0x00000010   
#define FILE_NOTIFY_CHANGE_LAST_ACCESS      0x00000020   
#define FILE_NOTIFY_CHANGE_CREATION         0x00000040   
#define FILE_NOTIFY_CHANGE_SECURITY         0x00000100   
#define FILE_ACTION_ADDED                   0x00000001   
#define FILE_ACTION_REMOVED                 0x00000002   
#define FILE_ACTION_MODIFIED                0x00000003   
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004   
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005   
#define MAILSLOT_NO_MESSAGE                 ((DWORD)-1) 
#define MAILSLOT_WAIT_FOREVER               ((DWORD)-1) 
#define FILE_CASE_SENSITIVE_SEARCH          0x00000001  
#define FILE_CASE_PRESERVED_NAMES           0x00000002  
#define FILE_UNICODE_ON_DISK                0x00000004  
#define FILE_PERSISTENT_ACLS                0x00000008  
#define FILE_FILE_COMPRESSION               0x00000010  
#define FILE_VOLUME_QUOTAS                  0x00000020  
#define FILE_SUPPORTS_SPARSE_FILES          0x00000040  
#define FILE_SUPPORTS_REPARSE_POINTS        0x00000080  
#define FILE_SUPPORTS_REMOTE_STORAGE        0x00000100  
#define FILE_VOLUME_IS_COMPRESSED           0x00008000  
#define FILE_SUPPORTS_OBJECT_IDS            0x00010000  
#define FILE_SUPPORTS_ENCRYPTION            0x00020000  
#define FILE_NAMED_STREAMS                  0x00040000  
#define FILE_READ_ONLY_VOLUME               0x00080000  
#define FILE_SEQUENTIAL_WRITE_ONCE          0x00100000  
#define FILE_SUPPORTS_TRANSACTIONS          0x00200000  
#define FILE_SUPPORTS_HARD_LINKS            0x00400000  
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES   0x00800000  
#define FILE_SUPPORTS_OPEN_BY_FILE_ID       0x01000000  
#define FILE_SUPPORTS_USN_JOURNAL           0x02000000  
#endif // _WINNT_


//////////////
// ByteOffset parameters
//////////////
#ifndef FILE_WRITE_TO_END_OF_FILE
#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#endif
#ifndef FILE_USE_FILE_POINTER_POSITION
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe
#endif

//////////////
// File Mapping (MMAP)
//////////////

#ifndef _WINNT_
#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                            SECTION_MAP_WRITE |      \
                            SECTION_MAP_READ |       \
                            SECTION_MAP_EXECUTE |    \
                            SECTION_EXTEND_SIZE)
#endif // _WINNT_

#ifndef _WINBASE_
#define FILE_MAP_COPY       SECTION_QUERY
#define FILE_MAP_WRITE      SECTION_MAP_WRITE
#define FILE_MAP_READ       SECTION_MAP_READ
#define FILE_MAP_ALL_ACCESS SECTION_ALL_ACCESS
#define FILE_MAP_EXECUTE    SECTION_MAP_EXECUTE_EXPLICIT    // not included in FILE_MAP_ALL_ACCESS
#endif // _WINBASE_

#ifndef _WINNT_
#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400     
#define MEM_COMMIT           0x1000     
#define MEM_RESERVE          0x2000     
#define MEM_DECOMMIT         0x4000     
#define MEM_RELEASE          0x8000     
#define MEM_FREE            0x10000     
#define MEM_PRIVATE         0x20000     
#define MEM_MAPPED          0x40000     
#define MEM_RESET           0x80000     
#define MEM_TOP_DOWN       0x100000     
#define MEM_WRITE_WATCH    0x200000     
#define MEM_PHYSICAL       0x400000     
#define MEM_ROTATE         0x800000     
#define MEM_LARGE_PAGES  0x20000000     
#define MEM_4MB_PAGES    0x80000000     
#define SEC_FILE           0x800000     
#define SEC_IMAGE         0x1000000     
#define SEC_PROTECTED_IMAGE  0x2000000  
#define SEC_RESERVE       0x4000000     
#define SEC_COMMIT        0x8000000     
#define SEC_NOCACHE      0x10000000     
#define SEC_WRITECOMBINE 0x40000000     
#define SEC_LARGE_PAGES  0x80000000     
#define MEM_IMAGE         SEC_IMAGE     
#define WRITE_WATCH_FLAG_RESET 0x01     
#endif // _WINNT_


#define VM_LOCK_1		0x0001	// This is used, when calling KERNEL32.DLL VirtualLock routine
#define VM_LOCK_2		0x0002	// This require SE_LOCK_MEMORY_NAME privilege


//////////////
// File Control
//////////////

#ifndef _WINNT_
#define DUPLICATE_CLOSE_SOURCE      0x00000001
#define DUPLICATE_SAME_ACCESS       0x00000002
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004
#endif // _WINNT_


//////////////
// Processor Info
//////////////

#ifndef _WINNT_
#define PROCESSOR_INTEL_386     386
#define PROCESSOR_INTEL_486     486
#define PROCESSOR_INTEL_PENTIUM 586
#define PROCESSOR_INTEL_IA64    2200
#define PROCESSOR_AMD_X8664     8664
#define PROCESSOR_MIPS_R4000    4000    // incl R4101 & R3910 for Windows CE
#define PROCESSOR_ALPHA_21064   21064
#define PROCESSOR_PPC_601       601
#define PROCESSOR_PPC_603       603
#define PROCESSOR_PPC_604       604
#define PROCESSOR_PPC_620       620
#define PROCESSOR_HITACHI_SH3   10003   // Windows CE
#define PROCESSOR_HITACHI_SH3E  10004   // Windows CE
#define PROCESSOR_HITACHI_SH4   10005   // Windows CE
#define PROCESSOR_MOTOROLA_821  821     // Windows CE
#define PROCESSOR_SHx_SH3       103     // Windows CE
#define PROCESSOR_SHx_SH4       104     // Windows CE
#define PROCESSOR_STRONGARM     2577    // Windows CE - 0xA11
#define PROCESSOR_ARM720        1824    // Windows CE - 0x720
#define PROCESSOR_ARM820        2080    // Windows CE - 0x820
#define PROCESSOR_ARM920        2336    // Windows CE - 0x920
#define PROCESSOR_ARM_7TDMI     70001   // Windows CE
#define PROCESSOR_OPTIL         0x494f  // MSIL

#define PROCESSOR_ARCHITECTURE_INTEL            0
#define PROCESSOR_ARCHITECTURE_MIPS             1
#define PROCESSOR_ARCHITECTURE_ALPHA            2
#define PROCESSOR_ARCHITECTURE_PPC              3
#define PROCESSOR_ARCHITECTURE_SHX              4
#define PROCESSOR_ARCHITECTURE_ARM              5
#define PROCESSOR_ARCHITECTURE_IA64             6
#define PROCESSOR_ARCHITECTURE_ALPHA64          7
#define PROCESSOR_ARCHITECTURE_MSIL             8
#define PROCESSOR_ARCHITECTURE_AMD64            9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64    10

#define PROCESSOR_ARCHITECTURE_UNKNOWN          0xFFFF
#endif // _WINNT_

//////////////
// I/O Completion Access Rights
//////////////
#define IO_COMPLETION_QUERY_STATE               0x0001
#define IO_COMPLETION_MODIFY_STATE              0x0002
#define IO_COMPLETION_ALL_ACCESS                \
			(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3)


//////////////
// Pipe Flags
//////////////
#define FILE_PIPE_BYTE_STREAM_TYPE              0x00000000
#define FILE_PIPE_MESSAGE_TYPE                  0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE              0x00000000
#define FILE_PIPE_MESSAGE_MODE                  0x00000001
#define FILE_PIPE_QUEUE_OPERATION               0x00000000
#define FILE_PIPE_COMPLETE_OPERATION            0x00000001
#define FILE_PIPE_INBOUND                       0x00000000
#define FILE_PIPE_OUTBOUND                      0x00000001
#define FILE_PIPE_FULL_DUPLEX                   0x00000002
#define FILE_PIPE_CLIENT_END                    0x00000000
#define FILE_PIPE_SERVER_END                    0x00000001


//////////////////////////////////////////
// NTDLL Structures
//////////////////////////////////////////

typedef struct _CLIENT_ID {
	/* These are numeric ids */
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _GENERIC_MAPPING {
	ACCESS_MASK   GenericRead;
	ACCESS_MASK   GenericWrite;
	ACCESS_MASK   GenericExecute;
	ACCESS_MASK   GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

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

#ifndef _WINNT_
#define EXCEPTION_MAXIMUM_PARAMETERS   15
typedef struct _EXCEPTION_RECORD {
	DWORD                     ExceptionCode;
	DWORD                     ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID                     ExceptionAddress;
	DWORD                     NumberParameters;
	ULONG_PTR                 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;
#endif // _WINNT_

// DebugInfoClassMask
#define PDI_MODULES       0x01
#define PDI_BACKTRACE     0x02
#define PDI_HEAPS         0x04
#define PDI_HEAP_TAGS     0x08
#define PDI_HEAP_BLOCKS   0x10
#define PDI_LOCKS         0x20

typedef struct _DEBUG_BUFFER {
	HANDLE  SectionHandle;
	PVOID   SectionBase;
	PVOID   RemoteSectionBase;
	ULONG   SectionBaseDelta;
	HANDLE  EventPairHandle;
	ULONG   Unknown[2];
	HANDLE  RemoteThreadHandle;
	ULONG   InfoClassMask;
	ULONG   SizeOfInfo;
	ULONG   AllocatedSize;
	ULONG   SectionSize;
	PVOID   ModuleInformation;
	PVOID   BackTraceInformation;
	PVOID   HeapInformation;
	PVOID   LockInformation;
	PVOID   Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

typedef struct _DEBUG_HEAP_INFORMATION {
	ULONG   Base;        // 0x00
	ULONG   Flags;       // 0x04
	USHORT  Granularity; // 0x08
	USHORT  Unknown;     // 0x0A
	ULONG   Allocated;   // 0x0C
	ULONG   Committed;   // 0x10
	ULONG   TagCount;    // 0x14
	ULONG   BlockCount;  // 0x18
	ULONG   Reserved[7]; // 0x1C
	PVOID   Tags;        // 0x38
	PVOID   Blocks;      // 0x3C Heap block pointer for this node.
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION; 

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS                  ExitStatus;
	PVOID                     PebBaseAddress; // PPEB_VISTA_7
	KAFFINITY                 AffinityMask;
	KPRIORITY                 BasePriority;
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
	USHORT          Flags;
	USHORT          Length;
	ULONG           TimeStamp;
	UNICODE_STRING  DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
	UNICODE_STRING  DosPath;
	HANDLE          Handle;
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

typedef enum _PNP_VETO_TYPE {
	PNP_VetoTypeUnknown = 0,
	PNP_VetoLegacyDevice = 1,
	PNP_VetoPendingClose = 2,
	PNP_VetoWindowsApp = 3,
	PNP_VetoWindowsService = 4,
	PNP_VetoOutstandingOpen = 5,
	PNP_VetoDevice = 6,
	PNP_VetoDriver = 7,
	PNP_VetoIllegalDeviceRequest = 8,
	PNP_VetoInsufficientPower = 9,
	PNP_VetoNonDisableable = 10,
	PNP_VetoLegacyDriver = 11,
	PNP_VetoInsufficientRights = 12,
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;


typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

#ifndef _WINNT_
typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID                   BaseAddress;
	PVOID                   AllocationBase;
	ULONG                   AllocationProtect;
	ULONG                   RegionSize;
	ULONG                   State;
	ULONG                   Protect;
	ULONG                   Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
#endif // _WINNT_


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

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG      Reserved;
	ULONG      TimerResolution;
	ULONG      PageSize;
	ULONG      NumberOfPhysicalPages;
	ULONG      LowestPhysicalPageNumber;
	ULONG      HighestPhysicalPageNumber;
	ULONG      AllocationGranularity;
	ULONG_PTR  MinimumUserModeAddress;
	ULONG_PTR  MaximumUserModeAddress;
	ULONG_PTR  ActiveProcessorsAffinityMask;
	CCHAR      NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION {
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG  ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleProcessTime;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG IoReadOperationCount;
	ULONG IoWriteOperationCount;
	ULONG IoOtherOperationCount;
	ULONG AvailablePages;
	ULONG CommittedPages;
	ULONG CommitLimit;
	ULONG PeakCommitment;
	ULONG PageFaultCount;
	ULONG CopyOnWriteCount;
	ULONG TransitionCount;
	ULONG CacheTransitionCount;
	ULONG DemandZeroCount;
	ULONG PageReadCount;
	ULONG PageReadIoCount;
	ULONG CacheReadCount;
	ULONG CacheIoCount;
	ULONG DirtyPagesWriteCount;
	ULONG DirtyWriteIoCount;
	ULONG MappedPagesWriteCount;
	ULONG MappedWriteIoCount;
	ULONG PagedPoolPages;
	ULONG NonPagedPoolPages;
	ULONG PagedPoolAllocs;
	ULONG PagedPoolFrees;
	ULONG NonPagedPoolAllocs;
	ULONG NonPagedPoolFrees;
	ULONG FreeSystemPtes;
	ULONG ResidentSystemCodePage;
	ULONG TotalSystemDriverPages;
	ULONG TotalSystemCodePages;
	ULONG NonPagedPoolLookasideHits;
	ULONG PagedPoolLookasideHits;
	ULONG Spare3Count;
	ULONG ResidentSystemCachePage;
	ULONG ResidentPagedPoolPage;
	ULONG ResidentSystemDriverPage;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadResourceMiss;
	ULONG CcFastReadNotPossible;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG ContextSwitches;
	ULONG FirstLevelTbFills;
	ULONG SecondLevelTbFills;
	ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	LONG           BasePriority;
	ULONG          ContextSwitches;
	ULONG          ThreadState;
	ULONG          WaitReason;
	ULONG          PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
//#ifndef _WIN64
//C_ASSERT(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40); // Must be 8-byte aligned
//#endif

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG           NextEntryOffset;
	ULONG           NumberOfThreads;
	LARGE_INTEGER   WorkingSetPrivateSize; //VISTA
	ULONG           HardFaultCount; //WIN7
	ULONG           NumberOfThreadsHighWatermark; //WIN7
	ULONGLONG       CycleTime; //WIN7
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ImageName;
	KPRIORITY       BasePriority;
	HANDLE          UniqueProcessId;
	HANDLE          InheritedFromUniqueProcessId;
	ULONG           HandleCount;
	ULONG           SessionId;
	ULONG_PTR       PageDirectoryBase;

	//
	// This part corresponds to VM_COUNTERS_EX.
	// NOTE: *NOT* THE SAME AS VM_COUNTERS!
	//
	SIZE_T          PeakVirtualSize;
	SIZE_T          VirtualSize;
	ULONG           PageFaultCount;
	SIZE_T          PeakWorkingSetSize;
	SIZE_T          WorkingSetSize;
	SIZE_T          QuotaPeakPagedPoolUsage;
	SIZE_T          QuotaPagedPoolUsage;
	SIZE_T          QuotaPeakNonPagedPoolUsage;
	SIZE_T          QuotaNonPagedPoolUsage;
	SIZE_T          PagefileUsage;
	SIZE_T          PeakPagefileUsage;
	SIZE_T          PrivatePageCount;

	//
	// This part corresponds to IO_COUNTERS
	//
	LARGE_INTEGER   ReadOperationCount;
	LARGE_INTEGER   WriteOperationCount;
	LARGE_INTEGER   OtherOperationCount;
	LARGE_INTEGER   ReadTransferCount;
	LARGE_INTEGER   WriteTransferCount;
	LARGE_INTEGER   OtherTransferCount;
	//    SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
//#ifndef _WIN64
//C_ASSERT(sizeof(SYSTEM_PROCESS_INFORMATION) == 0xB8); // Must be 8-byte aligned
//#endif

typedef struct _SYSTEM_CALL_COUNT_INFORMATION {
	ULONG   Length;
	ULONG   NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_DEVICE_INFORMATION {
	ULONG   NumberOfDisks;
	ULONG   NumberOfFloppies;
	ULONG   NumberOfCdRoms;
	ULONG   NumberOfTapes;
	ULONG   NumberOfSerialPorts;
	ULONG   NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER   IdleTime;
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   DpcTime;
	LARGE_INTEGER   InterruptTime;
	ULONG           InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_FLAGS_INFORMATION {
	ULONG   Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

typedef struct _SYSTEM_CALL_TIME_INFORMATION {
	ULONG          Length;
	ULONG          TotalCalls;
	LARGE_INTEGER  TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY {
	BOOLEAN            Allocated;
	BOOLEAN            Spare0;
	USHORT             AllocatorBackTraceIndex;
	ULONG              Size;
	union {
		UCHAR          Tag[4];
		ULONG          TagUlong;
		PVOID          ProcessChargedQuota;
	};
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION {
	SIZE_T             TotalSize;
	PVOID              FirstEntry;
	USHORT             EntryOverhead;
	BOOLEAN            PoolTagPresent;
	BOOLEAN            Spare0;
	ULONG              NumberOfEntries;
	SYSTEM_POOL_ENTRY  Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT      UniqueProcessId;
	USHORT      CreatorBackTraceIndex;
	UCHAR       ObjectTypeIndex;
	UCHAR       HandleAttributes;
	USHORT      HandleValue;
	PVOID       Object;
	ULONG       GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG                           NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO  Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION {
	ULONG            NextEntryOffset;
	ULONG            NumberOfObjects;
	ULONG            NumberOfHandles;
	ULONG            TypeIndex;
	ULONG            InvalidAttributes;
	GENERIC_MAPPING  GenericMapping;
	ULONG            ValidAccessMask;
	ULONG            PoolType;
	BOOLEAN          SecurityRequired;
	BOOLEAN          WaitableObject;
	UNICODE_STRING   TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING   Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION {
	ULONG                    NextEntryOffset;
	PVOID                    Object;
	HANDLE                   CreatorUniqueProcess;
	USHORT                   CreatorBackTraceIndex;
	USHORT                   Flags;
	LONG                     PointerCount;
	LONG                     HandleCount;
	ULONG                    PagedPoolCharge;
	ULONG                    NonPagedPoolCharge;
	HANDLE                   ExclusiveProcessId;
	PVOID                    SecurityDescriptor;
	OBJECT_NAME_INFORMATION  NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION {
	ULONG           NextEntryOffset;
	ULONG           TotalSize;
	ULONG           TotalInUse;
	ULONG           PeakUsage;
	UNICODE_STRING  PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
	SIZE_T  CurrentSize;
	SIZE_T  PeakSize;
	ULONG   PageFaultCount;
	SIZE_T  MinimumWorkingSet;
	SIZE_T  MaximumWorkingSet;
	SIZE_T  CurrentSizeIncludingTransitionInPages;
	SIZE_T  PeakSizeIncludingTransitionInPages;
	ULONG   TransitionRePurposeCount;
	ULONG   Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

typedef struct _SYSTEM_POOLTAG {
	union {
		UCHAR   Tag[4];
		ULONG   TagUlong;
	};
	ULONG       PagedAllocs;
	ULONG       PagedFrees;
	SIZE_T      PagedUsed;
	ULONG       NonPagedAllocs;
	ULONG       NonPagedFrees;
	SIZE_T      NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION {
	ULONG           Count;
	SYSTEM_POOLTAG  TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION {
	ULONG   ContextSwitches;
	ULONG   DpcCount;
	ULONG   DpcRate;
	ULONG   TimeIncrement;
	ULONG   DpcBypassCount;
	ULONG   ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION {
	ULONG   Spare;
	ULONG   DpcQueueDepth;
	ULONG   MinimumDpcRate;
	ULONG   AdjustDpcThreshold;
	ULONG   IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

typedef struct _SYSTEM_MEMORY_INFO {
	PUCHAR   StringOffset;
	USHORT   ValidCount;
	USHORT   TransitionCount;
	USHORT   ModifiedCount;
	USHORT   PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION {
	ULONG               InfoSize;
	ULONG               StringStart;
	SYSTEM_MEMORY_INFO  Memory[1];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

typedef struct _SYSTEM_GDI_DRIVER_INFORMATION {
	UNICODE_STRING           DriverName;
	PVOID                    ImageAddress;
	PVOID                    SectionPointer;
	PVOID                    EntryPoint;
	PIMAGE_EXPORT_DIRECTORY  ExportSectionPointer;
	ULONG                    ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION {
	ULONG     TimeAdjustment;
	ULONG     TimeIncrement;
	BOOLEAN   Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION {
	ULONG     TimeAdjustment;
	BOOLEAN   Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_REF_TRACE_INFORMATION {
	UCHAR            TraceEnable;
	UCHAR            TracePermanent;
	UNICODE_STRING   TraceProcessName;
	UNICODE_STRING   TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION {
	ULONG   AlignmentFixupCount;
	ULONG   ExceptionDispatchCount;
	ULONG   FloatingEmulationCount;
	ULONG   ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

typedef struct _SYSTEM_CRASH_STATE_INFORMATION {
	ULONG   ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN   KernelDebuggerEnabled;
	BOOLEAN   KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION {
	ULONG   ContextSwitches;
	ULONG   FindAny;
	ULONG   FindLast;
	ULONG   FindIdeal;
	ULONG   IdleAny;
	ULONG   IdleCurrent;
	ULONG   IdleLast;
	ULONG   IdleIdeal;
	ULONG   PreemptAny;
	ULONG   PreemptCurrent;
	ULONG   PreemptLast;
	ULONG   SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG    RegistryQuotaAllowed;
	ULONG    RegistryQuotaUsed;
	SIZE_T   PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;


typedef enum _INTERFACE_TYPE {
	InterfaceTypeUndefined = -1,
	Internal,
	Isa,
	Eisa,
	MicroChannel,
	TurboChannel,
	PCIBus,
	VMEBus,
	NuBus,
	PCMCIABus,
	CBus,
	MPIBus,
	MPSABus,
	ProcessorInternal,
	InternalPowerBus,
	PNPISABus,
	PNPBus,
	Vmcs,
	MaximumInterfaceType
} INTERFACE_TYPE, *PINTERFACE_TYPE;

typedef enum _PLUGPLAY_BUS_CLASS {
	SystemBus,
	PlugPlayVirtualBus,
	MaxPlugPlayBusClass
} PLUGPLAY_BUS_CLASS, *PPLUGPLAY_BUS_CLASS;

typedef enum _PLUGPLAY_VIRTUAL_BUS_TYPE {
	Root,
	MaxPlugPlayVirtualBusType
} PLUGPLAY_VIRTUAL_BUS_TYPE, *PPLUGPLAY_VIRTUAL_BUS_TYPE;

typedef struct _PLUGPLAY_BUS_TYPE {
	PLUGPLAY_BUS_CLASS             BusClass;
	union {
		INTERFACE_TYPE             SystemBusType;
		PLUGPLAY_VIRTUAL_BUS_TYPE  PlugPlayVirtualBusType;
	};
} PLUGPLAY_BUS_TYPE, *PPLUGPLAY_BUS_TYPE;

#define MAX_BUS_NAME 24

typedef struct _PLUGPLAY_BUS_INSTANCE {
	PLUGPLAY_BUS_TYPE  BusType;
	ULONG              BusNumber;
	WCHAR              BusName[MAX_BUS_NAME];
} PLUGPLAY_BUS_INSTANCE, *PPLUGPLAY_BUS_INSTANCE;

typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION {
	ULONG                  BusCount;
	PLUGPLAY_BUS_INSTANCE  BusInstance[1];
} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

typedef struct _SYSTEM_POWER_INFORMATION_NATIVE {
	BOOLEAN         SystemSuspendSupported;
	BOOLEAN         SystemHibernateSupported;
	BOOLEAN         ResumeTimerSupportsSuspend;
	BOOLEAN         ResumeTimerSupportsHibernate;
	BOOLEAN         LidSupported;
	BOOLEAN         TurboSettingSupported;
	BOOLEAN         TurboMode;
	BOOLEAN         SystemAcOrDc;
	BOOLEAN         PowerDownDisabled;
	LARGE_INTEGER   SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION {
	PNP_VETO_TYPE    VetoType;
	UNICODE_STRING   VetoDriver;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION {
	USHORT  CurrentDepth;
	USHORT  MaximumDepth;
	ULONG   TotalAllocates;
	ULONG   AllocateMisses;
	ULONG   TotalFrees;
	ULONG   FreeMisses;
	ULONG   Type;
	ULONG   Tag;
	ULONG   Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

typedef struct _SYSTEM_INFO {
	union {
		DWORD  dwOemId;
		struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		};
	};
	DWORD     dwPageSize;
	LPVOID    lpMinimumApplicationAddress;
	LPVOID    lpMaximumApplicationAddress;
	DWORD_PTR dwActiveProcessorMask;
	DWORD     dwNumberOfProcessors;
	DWORD     dwProcessorType;
	DWORD     dwAllocationGranularity;
	WORD      wProcessorLevel;
	WORD      wProcessorRevision;
} SYSTEM_INFO, *PSYSTEM_INFO, *LPSYSTEM_INFO;


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

#ifndef _WINNT_
#ifdef _WIN64 //) || defined(_AMD64_) || defined(_M_AMD64)

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];

#if defined(_WIN64)
    M128A XmmRegisters[16];
    BYTE  Reserved4[96];
#else
    M128A XmmRegisters[8];
    BYTE  Reserved4[192];

    DWORD   StackControl[7];    // KERNEL_STACK_CONTROL structure actualy
    DWORD   Cr0NpxState;
#endif
} XSAVE_FORMAT, *PXSAVE_FORMAT;
typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;

	DWORD ContextFlags;
	DWORD MxCsr;

	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;

	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;

	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;

	DWORD64 Rip;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	M128A VectorRegister[26];
	DWORD64 VectorControl;

	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

#else  // !_WIN64
#define SIZE_OF_80387_REGISTERS        80

typedef struct _FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
	DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA;
typedef FLOATING_SAVE_AREA *PFLOATING_SAVE_AREA;

#define MAXIMUM_SUPPORTED_EXTENSION    512
#include "pshpack4.h"
typedef struct _CONTEXT {

	DWORD ContextFlags;

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	FLOATING_SAVE_AREA FloatSave;

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;

	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;
typedef CONTEXT *PCONTEXT;
#include "poppack.h"

#endif // _WIN64
#endif // _WINNT_

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

#ifndef _WINNT_
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
#endif // _WINNT_

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

#ifndef _WINNT_
typedef struct _PROCESSOR_NUMBER {
	WORD   Group;
	BYTE  Number;
	BYTE  Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;
#endif // _WINNT_

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


typedef enum _SECTION_INHERIT {
	ViewShare=1,
	ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;


typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
    FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG                   NextEntryOffset;
	BYTE                    Flags;
	BYTE                    EaNameLength;
	USHORT                  EaValueLength;
	CHAR                    EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER           CreationTime;
	LARGE_INTEGER           LastAccessTime;
	LARGE_INTEGER           LastWriteTime;
	LARGE_INTEGER           ChangeTime;
	ULONG                   FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER           AllocationSize;
	LARGE_INTEGER           EndOfFile;
	ULONG                   NumberOfLinks;
	BOOLEAN                 DeletePending;
	BOOLEAN                 Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
	ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
	ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
	ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
	ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
	FILE_BASIC_INFORMATION     BasicInformation;
	FILE_STANDARD_INFORMATION  StandardInformation;
	FILE_INTERNAL_INFORMATION  InternalInformation;
	FILE_EA_INFORMATION        EaInformation;
	FILE_ACCESS_INFORMATION    AccessInformation;
	FILE_POSITION_INFORMATION  PositionInformation;
	FILE_MODE_INFORMATION      ModeInformation;
	FILE_ALIGNMENT_INFORMATION AlignmentInformation;
	FILE_NAME_INFORMATION      NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER  AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER  EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
    LARGE_INTEGER  ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          FileIndex;
    LARGE_INTEGER  CreationTime;
    LARGE_INTEGER  LastAccessTime;
    LARGE_INTEGER  LastWriteTime;
    LARGE_INTEGER  ChangeTime;
    LARGE_INTEGER  EndOfFile;
    LARGE_INTEGER  AllocationSize;
    ULONG          FileAttributes;
    ULONG          FileNameLength;
    WCHAR          FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION {
    PVOID            KeyContext;
    PVOID            ApcContext;
    IO_STATUS_BLOCK  IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    ULONG  FileAttributes;
    ULONG  ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_PIPE_WAIT_FOR_BUFFER {
    LARGE_INTEGER  Timeout;
    ULONG          NameLength;
    BOOLEAN        TimeoutSpecified;
    WCHAR          Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;

typedef struct _FILE_PIPE_PEEK_BUFFER {
    ULONG          NamedPipeState;
    ULONG          ReadDataAvailable;
    ULONG          NumberOfMessages;
    ULONG          MessageLength;
    CHAR           Data[1];
} FILE_PIPE_PEEK_BUFFER, *PFILE_PIPE_PEEK_BUFFER;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _FILE_FS_DEVICE_INFORMATION {
    DEVICE_TYPE   DeviceType;
    ULONG         Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG  FileSystemAttributes;
    ULONG  MaximumComponentNameLength;
    ULONG  FileSystemNameLength;
    WCHAR  FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION {
    LARGE_INTEGER   TotalAllocationUnits;
    LARGE_INTEGER   AvailableAllocationUnits;
    ULONG           SectorsPerAllocationUnit;
    ULONG           BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
    LARGE_INTEGER   TotalAllocationUnits;
    LARGE_INTEGER   CallerAvailableAllocationUnits;
    LARGE_INTEGER   ActualAvailableAllocationUnits;
    ULONG           SectorsPerAllocationUnit;
    ULONG           BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_LABEL_INFORMATION {
    ULONG  VolumeLabelLength;
    WCHAR  VolumeLabel[1];
} FILE_FS_LABEL_INFORMATION, *PFILE_FS_LABEL_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER  VolumeCreationTime;
    ULONG          VolumeSerialNumber;
    ULONG          VolumeLabelLength;
    BOOLEAN        SupportsObjects;
    WCHAR          VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;



#define RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER   0x1

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
	PACTIVATION_CONTEXT                         ActivationContext;
	ULONG                                       Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC {
	SIZE_T                              Size;
	ULONG                               Format;
	RTL_ACTIVATION_CONTEXT_STACK_FRAME  Frame;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED {
	SIZE_T                              Size;
	ULONG                               Format;
	RTL_ACTIVATION_CONTEXT_STACK_FRAME  Frame;
	PVOID                               Extra1;
	PVOID                               Extra2;
	PVOID                               Extra3;
	PVOID                               Extra4;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;

typedef RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;
typedef PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;


//////////////////////////////////////////
// Structure for NTDLL APIs
//////////////////////////////////////////

typedef struct _st_ntsc {

	/////////////////////
	// System
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQuerySystemInformation) (
		__in      SYSTEM_INFORMATION_CLASS SystemInformationClass,
		__inout   PVOID                    SystemInformation,
		__in      ULONG                    SystemInformationLength,
		__out_opt PULONG                   ReturnLength
		);

	/////////////////////
	// Process ENV Block
	/////////////////////

	NTSYSAPI_N PPEB_VISTA_7 (NTAPI *FP_RtlGetCurrentPeb) (void);


	/////////////////////
	// Context
	/////////////////////

	NTSYSAPI_N VOID (NTAPI *FP_RtlCaptureContext) (
		__out PCONTEXT  ContextRecord
		);

	PRTL_ACTIVATION_CONTEXT_STACK_FRAME (FASTCALL *FP_RtlActivateActivationContextUnsafeFast) (
		__in PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME  Frame,  
		__in PVOID                                                 Context  
		);

	PRTL_ACTIVATION_CONTEXT_STACK_FRAME (FASTCALL *FP_RtlDeactivateActivationContextUnsafeFast) (
		__in PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME  Frame
		);


	/////////////////////
	// Debug Functions
	/////////////////////

	NTSYSAPI_N ULONG (NTAPI *FP_DbgPrint) (
		__in  LPCSTR Format,
		__in  ...
		);

	NTSYSAPI_N PDEBUG_BUFFER (NTAPI *FP_RtlCreateQueryDebugBuffer) (
		__in    ULONG          Size,
		__in    BOOLEAN        EventPair
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlQueryProcessDebugInformation) (
		__in    ULONG          ProcessId,
		__in    ULONG          DebugInfoClassMask,  // ref. MACRO - DebugInfoClassMask
		__inout PDEBUG_BUFFER  DebugBuffer
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDestroyQueryDebugBuffer) (
		__in    PDEBUG_BUFFER  DebugBuffer
		);
	

	/////////////////////
	// Error Functions
	/////////////////////

	NTSYSAPI_N DWORD (NTAPI *FP_RtlGetLastWin32Error) (void);
	
	NTSYSAPI_N VOID (NTAPI *FP_RtlSetLastWin32Error) (
		__in  DWORD  err
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlRaiseException) (
		__in PEXCEPTION_RECORD ExceptionRecord
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlRaiseStatus) (
		__in NTSTATUS Status
		);


	/////////////////////
	// ProcMon(Stack Trace) Functions
	/////////////////////


	/////////////////////
	// CloseHandle Functions : NtOpenProcess / NtOpenThread / NtCreateFile
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtClose) (
		__in      HANDLE Handle
		);


	/////////////////////
	// Memory Functions
	/////////////////////

	NTSYSAPI_N PVOID (NTAPI *FP_RtlAllocateHeap) (
		__in      PVOID   HeapHandle,
		__in_opt  ULONG   Flags,
		__in      SIZE_T  Size
		);

	NTSYSAPI_N PVOID (NTAPI *FP_RtlReAllocateHeap) (
		__in      PVOID   HeapHandle,
		__in_opt  ULONG   Flags,
		__in      PVOID   MemoryPointer,
		__in      SIZE_T  Size
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlFreeHeap) (
		__in      PVOID  HeapHandle,
		__in_opt  ULONG  Flags,
		__in      PVOID  HeapBase
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlZeroMemory) (
		__out  PVOID   Destination,
		__in   SIZE_T  Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlFillMemory) (
		__out  PVOID   Destination,
		__in   SIZE_T  Length,
		__in   UCHAR   Fill
		);

	NTSYSAPI_N SIZE_T (NTAPI *FP_RtlCompareMemory) (
		__in  const VOID  *Source1,
		__in  const VOID  *Source2,
		__in  SIZE_T       Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlCopyMemory) (
		__out  PVOID        Destination,
		__in   const PVOID  Source,
		__in   SIZE_T       Length
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlMoveMemory) (
		__out  PVOID        Destination,
		__in   const PVOID  Source,
		__in   SIZE_T       Length
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlFlushSecureMemoryCache) (
		__in     PVOID   MemoryCache,  
		__in_opt SIZE_T  MemoryLength
		);


	/////////////////////
	// Virtual Memory Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtCreateSection) ( // CreateFileMapping
		__out     PHANDLE             SectionHandle,
		__in      ACCESS_MASK         DesiredAccess,
		__in_opt  POBJECT_ATTRIBUTES  ObjectAttributes,
		__in_opt  PLARGE_INTEGER      MaximumSize,
		__in      ULONG               SectionPageProtection,
		__in      ULONG               AllocationAttributes,
		__in_opt  HANDLE              FileHandle
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtMapViewOfSection) ( // MapViewOfFile
		__in     HANDLE           SectionHandle,
		__in     HANDLE           ProcessHandle,
		__inout  PVOID           *BaseAddress,
		__in     ULONG_PTR        ZeroBits,
		__in     SIZE_T           CommitSize,
		__inout  PLARGE_INTEGER   SectionOffset,
		__inout  PSIZE_T          ViewSize,
		__in     SECTION_INHERIT  InheritDisposition,
		__in     ULONG            AllocationType,
		__in     ULONG            Win32Protect
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtUnmapViewOfSection) (
		__in      HANDLE ProcessHandle,
		__in_opt  PVOID BaseAddress
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtAllocateVirtualMemory) (
		__in     HANDLE     ProcessHandle,
		__inout  PVOID     *BaseAddress,
		__in     ULONG_PTR  ZeroBits,
		__inout  PSIZE_T    RegionSize,
		__in     ULONG      AllocationType,
		__in     ULONG      Protect
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtFreeVirtualMemory) (
		__in     HANDLE   ProcessHandle,
		__inout  PVOID   *BaseAddress,
		__inout  PSIZE_T  RegionSize,
		__in     ULONG    FreeType
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtFlushVirtualMemory) (
		__in     HANDLE            ProcessHandle,
		__inout  PVOID            *BaseAddress,
		__inout  PSIZE_T           RegionSize,
		__out    PIO_STATUS_BLOCK  IoStatus
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtLockVirtualMemory) (
		__in    HANDLE    ProcessHandle,
		__in    PVOID    *BaseAddress,
		__inout PULONG    NumberOfBytesToLock,
		__in    ULONG     LockOption
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtUnlockVirtualMemory) (
		__in    HANDLE      ProcessHandle,
		__in    PVOID      *BaseAddress,
		__inout PULONG      NumberOfBytesToUnlock,
		__in    ULONG       LockType
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
		__inout  PSTRING  DestinationString,
		__in     PCSZ     SourceString
		);

	// Same as RtlInitAnsiString
	//NTSYSAPI_N VOID (NTAPI *FP_RtlInitAnsiString) (
	//	__out     PANSI_STRING  DestinationString,
	//	__in_opt  PCSZ          SourceString
	//	);

	// Obsolete : Use  RtlUnicodeStringInit
	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlInitUnicodeString) (
		__out  PUNICODE_STRING  DestinationString,
		__in   PCWSTR           SourceString
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCreateUnicodeStringFromAsciiz) (
		__out PUNICODE_STRING  Destination,  
		__in  PCSZ             Source  
		);

	NTSYSAPI_N ULONG (NTAPI *FP_RtlAnsiStringToUnicodeSize) (
		 __in  PANSI_STRING AnsiString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAnsiStringToUnicodeString) (
		__inout  PUNICODE_STRING  DestinationString,
		__in     PCANSI_STRING    SourceString,
		__in     BOOLEAN          AllocateDestinationString
		);

	NTSYSAPI_N ULONG (NTAPI *FP_RtlUnicodeStringToAnsiSize) (
		__in  PUNICODE_STRING UnicodeString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlUnicodeStringToAnsiString) (
		__inout  PANSI_STRING      DestinationString,
		__in     PCUNICODE_STRING  SourceString,
		__in     BOOLEAN           AllocateDestinationString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCopyString) (
		__out     PSTRING        DestinationString,
		__in_opt  const STRING  *SourceString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCopyUnicodeString) (
		__out     PUNICODE_STRING   DestinationString,
		__in_opt  PCUNICODE_STRING  SourceString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendAsciizToString) (
		__inout PSTRING  Destination,  
		__in    PCSZ     Source  
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendStringToString) (
		__inout  PSTRING        Destination,
		__in     const STRING  *Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendUnicodeStringToString) (
		__inout  PUNICODE_STRING   Destination,
		__in     PCUNICODE_STRING  Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlAppendUnicodeToString) (
		__inout   PUNICODE_STRING  Destination,
		__in_opt  PCWSTR           Source
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlMultiAppendUnicodeStringBuffer) ( 
		__inout PRTL_UNICODE_STRING_BUFFER  pStrBuffer, 
		__in    ULONG                       numAddends, 
		__in    PCUNICODE_STRING            pAddends 
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlEqualString) (
		__in  const STRING  *String1,
		__in  const STRING  *String2,
		__in  BOOLEAN        CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlEqualUnicodeString) (
		__in  PCUNICODE_STRING  String1,
		__in  PCUNICODE_STRING  String2,
		__in  BOOLEAN           CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCompareString) (
		__in  const STRING  *String1,
		__in  const STRING  *String2,
		__in  BOOLEAN        CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlCompareUnicodeString) (
		__in  PCUNICODE_STRING  String1,
		__in  PCUNICODE_STRING  String2,
		__in  BOOLEAN           CaseInSensitive
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlUpperString) (
		__inout  PSTRING        DestinationString,
		__in     const STRING  *SourceString
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlUpcaseUnicodeString) (
		__inout  PUNICODE_STRING   DestinationString,
		__in     PCUNICODE_STRING  SourceString,
		__in     BOOLEAN           AllocateDestinationString
		);

	NTSYSAPI_N WCHAR (NTAPI *FP_RtlDowncaseUnicodeChar) (
		__in  WCHAR SourceCharacter
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDowncaseUnicodeString) (
		__inout PUNICODE_STRING   DestinationString,
		__in    PCUNICODE_STRING  SourceString,
		__in    BOOLEAN           AllocateDestinationString
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlIntegerToChar) (
		__in      ULONG  Value,  
		__in_opt  ULONG  Base,  
		__in      ULONG  Length,  
		__inout   PCHAR  str
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlIntegerToUnicodeString) (
		__in      ULONG            Value,
		__in_opt  ULONG            Base,
		__inout   PUNICODE_STRING  String
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCharToInteger) (
		__in      PCSZ   String,
		__in_opt  ULONG  Base,
		__out     PULONG Value
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlUnicodeStringToInteger) (
		__in      PCUNICODE_STRING String,
		__in_opt  ULONG            Base,
		__out     PULONG           Value
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
		__out    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
		__in     PUNICODE_STRING               ImagePathName,
		__in_opt PUNICODE_STRING               DllPath,
		__in_opt PUNICODE_STRING               CurrentDirectory,
		__in_opt PUNICODE_STRING               CommandLine,
		__in_opt PVOID                         Environment,
		__in_opt PUNICODE_STRING               WindowTitle,
		__in_opt PUNICODE_STRING               DesktopInfo,
		__in_opt PUNICODE_STRING               ShellInfo,
		__in_opt PUNICODE_STRING               RuntimeData
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDestroyProcessParameters) (
		__in    PRTL_USER_PROCESS_PARAMETERS pProcessParameters
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCreateUserProcess) (
		__in     PUNICODE_STRING               ImageFileName,
		__in     ULONG                         Attributes,
		__inout  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters,
		__in_opt PSECURITY_DESCRIPTOR          ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR          ThreadSecurityDescriptor,
		__in_opt HANDLE                        ParentProcess,
		__in     BOOLEAN                       InheritHandles,
		__in_opt HANDLE                        DebugPort,
		__in_opt HANDLE                        ExceptionPort,
		__out    PRTL_USER_PROCESS_INFORMATION ProcessInfo
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_CsrClientCallServer) (
		__inout PVOID Message,
		__inout PVOID Buffer,
		__in    ULONG Opcode,
		__in    ULONG BufferSize
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryInformationProcess) (
		__in       HANDLE            ProcessHandle,
		__in       PROCESSINFOCLASS  ProcessInformationClass,
		__out      PVOID             ProcessInformation,
		__in       ULONG             ProcessInformationLength,
		__out_opt  PULONG            ReturnLength
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlCloneUserProcess) (
		__in     ULONG                         ProcessFlags,
		__in_opt PSECURITY_DESCRIPTOR          ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR          ThreadSecurityDescriptor,
		__in_opt HANDLE                        DebugPort,
		__out    PRTL_USER_PROCESS_INFORMATION ProcessInformation
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlUpdateClonedCriticalSection) (
		__inout PRTL_CRITICAL_SECTION CriticalSection
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlUpdateClonedSRWLock) (
		__inout PRTL_SRWLOCK  SRWLock,
		__in    LOGICAL       Shared // TRUE to set to shared acquire
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlExitUserProcess) (
		__in NTSTATUS ExitStatus
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtWaitForSingleObject) (
		__in  HANDLE           Handle,
		__in  BOOLEAN          Alertable,
		__in  PLARGE_INTEGER   Timeout
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtOpenProcess) (
		__out     PHANDLE            ProcessHandle,
		__in      ACCESS_MASK        DesiredAccess,
		__in      POBJECT_ATTRIBUTES ObjectAttributes,
		__in_opt  PCLIENT_ID         ClientId
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
	// CriticalSection Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlInitializeCriticalSection) (
		__in PRTL_CRITICAL_SECTION pCriticalSection
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlInitializeCriticalSectionAndSpinCount) (
		__in PRTL_CRITICAL_SECTION pCriticalSection, 
		__in DWORD SpinCount
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlDeleteCriticalSection) (
		__in PRTL_CRITICAL_SECTION pCriticalSection
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlEnterCriticalSection) (
		__in PRTL_CRITICAL_SECTION pCriticalSection
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlLeaveCriticalSection) (
		__in PRTL_CRITICAL_SECTION pCriticalSection
		);

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlTryEnterCriticalSection) (
		__in PRTL_CRITICAL_SECTION pCriticalSection
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_RtlpWaitForCriticalSection) (
		__in PRTL_CRITICAL_SECTION  CriticalSection
		);

	NTSYSAPI_N VOID (NTAPI *FP_RtlpUnWaitCriticalSection) (
		__in PRTL_CRITICAL_SECTION  CriticalSection
		);


	/////////////////////
	// Keyed Event Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtCreateKeyedEvent) (
		__out     PHANDLE             handle,
		__in      ACCESS_MASK         access,
		__in_opt  POBJECT_ATTRIBUTES  attr,
		__in      ULONG               flags
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtOpenKeyedEvent) (
		__out     PHANDLE             handle,
		__in      ACCESS_MASK         access,
		__in      POBJECT_ATTRIBUTES  attr
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtWaitForKeyedEvent) (
		__in      HANDLE              handle,
		__in      PVOID               key,
		__in      BOOLEAN             alertable,
		__in_opt  PLARGE_INTEGER      mstimeout
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtReleaseKeyedEvent)(
		__in      HANDLE              handle,
		__in      PVOID               key,
		__in      BOOLEAN             alertable,
		__in_opt  PLARGE_INTEGER      mstimeout
		);


	/////////////////////
	// PATH Functions
	/////////////////////

	NTSYSAPI_N BOOLEAN (NTAPI *FP_RtlDosPathNameToNtPathName_U) (
		__in      PCWSTR           DosName,
		__out     PUNICODE_STRING  NtName,
		__out_opt PCWSTR          *DosFilePath,
		__out_opt PUNICODE_STRING  NtFilePath
		);


	/////////////////////
	// File Functions
	/////////////////////
	
	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryInformationFile) (
		__in   HANDLE                  FileHandle,
		__out  PIO_STATUS_BLOCK        IoStatusBlock,
		__out  PVOID                   FileInformation,
		__in   ULONG                   Length,
		__in   FILE_INFORMATION_CLASS  FileInformationClass
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtSetInformationFile) (
		__in   HANDLE                  FileHandle,
		__out  PIO_STATUS_BLOCK        IoStatusBlock,
		__out  PVOID                   FileInformation,
		__in   ULONG                   Length,
		__in   FILE_INFORMATION_CLASS  FileInformationClass
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtCreateFile) (
		__out     PHANDLE            FileHandle,
		__in      ACCESS_MASK        DesiredAccess,
		__in      POBJECT_ATTRIBUTES ObjectAttributes,
		__out     PIO_STATUS_BLOCK   IoStatusBlock,
		__in_opt  PLARGE_INTEGER     AllocationSize,
		__in      ULONG              FileAttributes,
		__in      ULONG              ShareAccess,
		__in      ULONG              CreateDisposition,
		__in      ULONG              CreateOptions,
		__in      PVOID              EaBuffer,
		__in      ULONG              EaLength
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtOpenFile) (
		__out  PHANDLE            FileHandle,
		__in   ACCESS_MASK        DesiredAccess,
		__in   POBJECT_ATTRIBUTES ObjectAttributes,
		__out  PIO_STATUS_BLOCK   IoStatusBlock,
		__in   ULONG              ShareAccess,
		__in   ULONG              OpenOptions
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtReadFile) (
		__in      HANDLE            FileHandle,
		__in_opt  HANDLE            Event,
		__in_opt  PVOID             ApcRoutine,    // PIO_APC_ROUTINE
		__in_opt  PVOID             ApcContext,
		__out     PIO_STATUS_BLOCK  IoStatusBlock,
		__out     PVOID             Buffer,
		__in      ULONG             Length,
		__in_opt  PLARGE_INTEGER    ByteOffset,
		__in_opt  PULONG            Key
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtWriteFile) (
		__in      HANDLE            FileHandle,
		__in_opt  HANDLE            Event,
		__in_opt  PVOID             ApcRoutine,    // PIO_APC_ROUTINE
		__in_opt  PVOID             ApcContext,
		__out     PIO_STATUS_BLOCK  IoStatusBlock,
		__in      PVOID             Buffer,
		__in      ULONG             Length,
		__in_opt  PLARGE_INTEGER    ByteOffset,
		__in_opt  PULONG            Key
		);


	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtCreateNamedPipeFile) (
		__out PHANDLE              NamedPipeFileHandle,
		__in  ACCESS_MASK          DesiredAccess,
		__in  POBJECT_ATTRIBUTES   ObjectAttributes,
		__out PIO_STATUS_BLOCK     IoStatusBlock,
		__in  ULONG                ShareAccess,
		__in  ULONG                CreateDisposition,
		__in  ULONG                CreateOptions,
		__in  BOOLEAN              WriteModeMessage,
		__in  BOOLEAN              ReadModeMessage,
		__in  BOOLEAN              NonBlocking,
		__in  ULONG                MaxInstances,
		__in  ULONG                InBufferSize,
		__in  ULONG                OutBufferSize,
		__in  PLARGE_INTEGER       DefaultTimeOut
		);





	/////////////////////
	// File Control Functions
	/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtDuplicateObject) (
		__in       HANDLE       SourceProcessHandle,
		__in       HANDLE       SourceHandle,
		__in_opt   HANDLE       TargetProcessHandle,
		__out_opt  PHANDLE      TargetHandle,
		__in       ACCESS_MASK  DesiredAccess,
		__in       ULONG        HandleAttributes,
		__in       ULONG        Options
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtLockFile) (
		__in      HANDLE FileHandle,
		__in_opt  HANDLE Event,
		__in_opt  PVOID ApcRoutine, // PIO_APC_ROUTINE
		__in_opt  PVOID ApcContext,
		__out     PIO_STATUS_BLOCK IoStatusBlock,
		__in      PLARGE_INTEGER ByteOffset,
		__in      PLARGE_INTEGER Length,
		__in      ULONG Key,
		__in      BOOLEAN FailImmediately,
		__in      BOOLEAN ExclusiveLock
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtUnlockFile) (
		__in   HANDLE FileHandle,
		__out  PIO_STATUS_BLOCK IoStatusBlock,
		__in   PLARGE_INTEGER ByteOffset,
		__in   PLARGE_INTEGER Length,
		__in   ULONG Key
		);



		/////////////////////
		// FileSystem Functions
		/////////////////////

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtQueryVolumeInformationFile) (
		__in   HANDLE                 FileHandle,
		__out  PIO_STATUS_BLOCK       IoStatusBlock,
		__out  PVOID                  FsInformation,
		__in   ULONG                  Length,
		__in   FS_INFORMATION_CLASS   FsInformationClass
		);

	NTSYSAPI_N NTSTATUS (NTAPI *FP_NtSetVolumeInformationFile) (
		__in   HANDLE                 FileHandle,
		__out  PIO_STATUS_BLOCK       IoStatusBlock,
		__out  PVOID                  FsInformation,
		__in   ULONG                  Length,
		__in   FS_INFORMATION_CLASS   FsInformationClass
		);


	/////////////////////
	// Time Functions
	/////////////////////

	NTSYSAPI_N ULONG (NTAPI *FP_NtGetTickCount) (void);


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
static FORCEINLINE PTEB_7 XbNtCurrentTeb(void) {
	return (PTEB_7)Xb__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}
#else  // !_WIN64
#define PcTeb 0x18
static FORCEINLINE PTEB_7 XbNtCurrentTeb(void) {
	__asm mov eax, fs:[PcTeb]
}
#endif // _WIN64
#else  // !_MSC_VER
#ifdef _WIN64
//#define PcTeb 0x30
static FORCEINLINE PTEB_7 XbNtCurrentTeb(void) {
	PTEB_7 _teb = NULL;
	__asm__ __volatile__("movl %%gs:0x30, %0\n"
						 : "=r" (_teb)
						);
	return _teb;
}
#else  // !_WIN64
//#define PcTeb 0x18
static FORCEINLINE PTEB_7 XbNtCurrentTeb(void) {
	PTEB_7 _teb = NULL;
	__asm__ __volatile__("movl %%fs:0x18, %0\n"
						 : "=r" (_teb)
						);
	return _teb;
}
#endif // _WIN64
#endif // _MSC_VER


//////////////////////////////////////////
// Function for getting structure-pointer
//////////////////////////////////////////
ntsc_t *ntdll_getFP();

#endif // __NTDLL_H__
