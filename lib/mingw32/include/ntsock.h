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

#ifndef __NTSOCK_H__
#define __NTSOCK_H__

#include "nttypes.h"

#if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)

//////////////////////////////////////////
// NTDLL MACRO
//////////////////////////////////////////


//////////////////////////////////////////
// NTSOCK Types
//////////////////////////////////////////

typedef UINT_PTR        SOCKET;
typedef unsigned int    GROUP;


//////////////////////////////////////////
// NTDLL MACRO
//////////////////////////////////////////

//////////////
// ERROR
//////////////

#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)

#define WSA_IO_PENDING          (997L)
#define WSA_IO_INCOMPLETE       (996L)
#define WSA_INVALID_HANDLE      (6L)
#define WSA_INVALID_PARAMETER   (87L)
#define WSA_NOT_ENOUGH_MEMORY   (8L)
#define WSA_OPERATION_ABORTED   (995L)

#define WSA_INVALID_EVENT       ((HANDLE)NULL)
#define WSA_MAXIMUM_WAIT_EVENTS (64)
#define WSA_WAIT_FAILED         ((DWORD)0xFFFFFFFF)
#define WSA_WAIT_EVENT_0        ((STATUS_WAIT_0 ) + 0)
#define WSA_WAIT_IO_COMPLETION  ((DWORD)0x000000C0L)
#define WSA_WAIT_TIMEOUT        (258L)
#define WSA_INFINITE            (0xFFFFFFFF)

#if !defined(_WINERROR_) && !defined(WSABASEERR)
#define WSAEINTR                         10004L
#define WSAEBADF                         10009L
#define WSAEACCES                        10013L
#define WSAEFAULT                        10014L
#define WSAEINVAL                        10022L
#define WSAEMFILE                        10024L
#define WSAEWOULDBLOCK                   10035L
#define WSAEINPROGRESS                   10036L
#define WSAEALREADY                      10037L
#define WSAENOTSOCK                      10038L
#define WSAEDESTADDRREQ                  10039L
#define WSAEMSGSIZE                      10040L
#define WSAEPROTOTYPE                    10041L
#define WSAENOPROTOOPT                   10042L
#define WSAEPROTONOSUPPORT               10043L
#define WSAESOCKTNOSUPPORT               10044L
#define WSAEOPNOTSUPP                    10045L
#define WSAEPFNOSUPPORT                  10046L
#define WSAEAFNOSUPPORT                  10047L
#define WSAEADDRINUSE                    10048L
#define WSAEADDRNOTAVAIL                 10049L
#define WSAENETDOWN                      10050L
#define WSAENETUNREACH                   10051L
#define WSAENETRESET                     10052L
#define WSAECONNABORTED                  10053L
#define WSAECONNRESET                    10054L
#define WSAENOBUFS                       10055L
#define WSAEISCONN                       10056L
#define WSAENOTCONN                      10057L
#define WSAESHUTDOWN                     10058L
#define WSAETOOMANYREFS                  10059L
#define WSAETIMEDOUT                     10060L
#define WSAECONNREFUSED                  10061L
#define WSAELOOP                         10062L
#define WSAENAMETOOLONG                  10063L
#define WSAEHOSTDOWN                     10064L
#define WSAEHOSTUNREACH                  10065L
#define WSAENOTEMPTY                     10066L
#define WSAEPROCLIM                      10067L
#define WSAEUSERS                        10068L
#define WSAEDQUOT                        10069L
#define WSAESTALE                        10070L
#define WSAEREMOTE                       10071L
#define WSASYSNOTREADY                   10091L
#define WSAVERNOTSUPPORTED               10092L
#define WSANOTINITIALISED                10093L
#define WSAEDISCON                       10101L
#define WSAENOMORE                       10102L
#define WSAECANCELLED                    10103L
#define WSAEINVALIDPROCTABLE             10104L
#define WSAEINVALIDPROVIDER              10105L
#define WSAEPROVIDERFAILEDINIT           10106L
#define WSASYSCALLFAILURE                10107L
#define WSASERVICE_NOT_FOUND             10108L
#define WSATYPE_NOT_FOUND                10109L
#define WSA_E_NO_MORE                    10110L
#define WSA_E_CANCELLED                  10111L
#define WSAEREFUSED                      10112L
#define WSAHOST_NOT_FOUND                11001L
#define WSATRY_AGAIN                     11002L
#define WSANO_RECOVERY                   11003L
#define WSANO_DATA                       11004L
#define WSA_QOS_RECEIVERS                11005L
#define WSA_QOS_SENDERS                  11006L
#define WSA_QOS_NO_SENDERS               11007L
#define WSA_QOS_NO_RECEIVERS             11008L
#define WSA_QOS_REQUEST_CONFIRMED        11009L
#define WSA_QOS_ADMISSION_FAILURE        11010L
#define WSA_QOS_POLICY_FAILURE           11011L
#define WSA_QOS_BAD_STYLE                11012L
#define WSA_QOS_BAD_OBJECT               11013L
#define WSA_QOS_TRAFFIC_CTRL_ERROR       11014L
#define WSA_QOS_GENERIC_ERROR            11015L
#define WSA_QOS_ESERVICETYPE             11016L
#define WSA_QOS_EFLOWSPEC                11017L
#define WSA_QOS_EPROVSPECBUF             11018L
#define WSA_QOS_EFILTERSTYLE             11019L
#define WSA_QOS_EFILTERTYPE              11020L
#define WSA_QOS_EFILTERCOUNT             11021L
#define WSA_QOS_EOBJLENGTH               11022L
#define WSA_QOS_EFLOWCOUNT               11023L
#define WSA_QOS_EUNKOWNPSOBJ             11024L
#define WSA_QOS_EPOLICYOBJ               11025L
#define WSA_QOS_EFLOWDESC                11026L
#define WSA_QOS_EPSFLOWSPEC              11027L
#define WSA_QOS_EPSFILTERSPEC            11028L
#define WSA_QOS_ESDMODEOBJ               11029L
#define WSA_QOS_ESHAPERATEOBJ            11030L
#define WSA_QOS_RESERVED_PETYPE          11031L
#define WSA_SECURE_HOST_NOT_FOUND        11032L
#define WSA_IPSEC_NAME_POLICY_ERROR      11033L
#endif // !_WINERROR_ && !WSABASEERR


//////////////
// ADDRESS
//////////////

#define ADDR_ANY                INADDR_ANY


//////////////
// WSADATA
//////////////

#define WSADESCRIPTION_LEN      256
#define WSASYS_STATUS_LEN       128


//////////////
// AF/TYPE/PROTOCOL
//////////////

#define XWSA_AF_UNSPEC          0
#define XWSA_AF_INET            2
#define XWSA_AF_IPX             6
#define XWSA_AF_APPLETALK       16
#define XWSA_AF_NETBIOS         17
#define XWSA_AF_INET6           23
#define XWSA_AF_IRDA            26
#define XWSA_AF_BTH             32

#define XWSA_SOCK_STREAM        1
#define XWSA_SOCK_DGRAM         2
#define XWSA_SOCK_RAW           3
#define XWSA_SOCK_RDM           4
#define XWSA_SOCK_SEQPACKET     5

#define XWSA_IPPROTO_ICMP       1
#define XWSA_IPPROTO_IGMP       2
#define XWSA_BTHPROTO_RFCOMM    3
#define XWSA_IPPROTO_TCP        6
#define XWSA_IPPROTO_UDP        17
#define XWSA_IPPROTO_ICMPV6     58
#define XWSA_IPPROTO_RM         113


//////////////////////////////////////////
// NTSOCK Structures
//////////////////////////////////////////

typedef struct WSAData {
	WORD                    wVersion;
	WORD                    wHighVersion;
#ifdef _WIN64
	unsigned short          iMaxSockets;
	unsigned short          iMaxUdpDg;
	char FAR *              lpVendorInfo;
	char                    szDescription[WSADESCRIPTION_LEN+1];
	char                    szSystemStatus[WSASYS_STATUS_LEN+1];
#else
	char                    szDescription[WSADESCRIPTION_LEN+1];
	char                    szSystemStatus[WSASYS_STATUS_LEN+1];
	unsigned short          iMaxSockets;
	unsigned short          iMaxUdpDg;
	char FAR *              lpVendorInfo;
#endif
} WSADATA, FAR * LPWSADATA;

#define MAX_PROTOCOL_CHAIN 7

#define BASE_PROTOCOL      1
#define LAYERED_PROTOCOL   0

typedef struct _WSAPROTOCOLCHAIN {
	int    ChainLen;
	DWORD  ChainEntries[MAX_PROTOCOL_CHAIN];
} WSAPROTOCOLCHAIN, FAR * LPWSAPROTOCOLCHAIN;

#define WSAPROTOCOL_LEN  255

typedef struct _WSAPROTOCOL_INFOA {
	DWORD            dwServiceFlags1;
	DWORD            dwServiceFlags2;
	DWORD            dwServiceFlags3;
	DWORD            dwServiceFlags4;
	DWORD            dwProviderFlags;
	GUID             ProviderId;
	DWORD            dwCatalogEntryId;
	WSAPROTOCOLCHAIN ProtocolChain;
	int              iVersion;
	int              iAddressFamily;
	int              iMaxSockAddr;
	int              iMinSockAddr;
	int              iSocketType;
	int              iProtocol;
	int              iProtocolMaxOffset;
	int              iNetworkByteOrder;
	int              iSecurityScheme;
	DWORD            dwMessageSize;
	DWORD            dwProviderReserved;
	CHAR             szProtocol[WSAPROTOCOL_LEN+1];
} WSAPROTOCOL_INFOA, FAR * LPWSAPROTOCOL_INFOA;

typedef WSAPROTOCOL_INFOA WSAPROTOCOL_INFO;
typedef LPWSAPROTOCOL_INFOA LPWSAPROTOCOL_INFO;

// for compatibility with LINUX definition {{{
#define WSA_FD_SETSIZE 1024

typedef struct _WSA_fd_set {
	unsigned int  fd_count;
	SOCKET        fd_array[WSA_FD_SETSIZE];
} WSA_fd_set;

typedef unsigned short _WSA_sa_family;

struct _WSA_sockaddr {
	_WSA_sa_family sa_family;
	char sa_data[14];
};
// }}}

#endif // !_WINSOCK2API_ && !_WINSOCKAPI_


//////////////////////////////////////////
// Structure for SOCKET(ws2_32.dll) APIs
//////////////////////////////////////////

typedef struct _st_ntsock {
	int (WSAAPI *FP_WSAStartup) (
		__in   WORD      wVersionRequested,
		__out  LPWSADATA lpWSAData
		);

	int (WSAAPI *FP_WSACleanup) (void);

	int (WSAAPI *FP_WSAGetLastError) (void);

	int (WSAAPI *FP_WSADuplicateSocketA) (
		__in   SOCKET             s,
		__in   DWORD              dwProcessId,
		__out  LPWSAPROTOCOL_INFO lpProtocolInfo
		);

	SOCKET (WSAAPI *FP_WSASocketA) (
		__in  int                af,
		__in  int                type,
		__in  int                protocol,
		__in  LPWSAPROTOCOL_INFO lpProtocolInfo,
		__in  GROUP              g,
		__in  DWORD              dwFlags
		);



	SOCKET (WSAAPI *FP_socket) (
		__in  int af,
		__in  int type,
		__in  int protocol
		);

	int (WSAAPI *FP_closesocket) (
		__in  SOCKET s
		);

	int (WSAAPI *FP_connect) (
		__in  SOCKET                      s,
		__in  const struct _WSA_sockaddr *name,
		__in  int                         namelen
		);

	int (WSAAPI *FP_recv) (
		__in   SOCKET  s,
		__out  char   *buf,
		__in   int     len,
		__in   int     flags
		);

	int (WSAAPI *FP_send) (
		__in   SOCKET  s,
		__out  char   *buf,
		__in   int     len,
		__in   int     flags
		);

	int (WSAAPI *FP_select) (
		__in     int nfds,
		__inout  WSA_fd_set *readfds,
		__inout  WSA_fd_set *writefds,
		__inout  WSA_fd_set *exceptfds,
		__in     const struct timeval *timeout
		);



} ntsock_t;


//////////////////////////////////////////
// Function for getting structure-pointer
//////////////////////////////////////////
ntsock_t *ntsock_getFP();

#endif // __NTSOCK_H__
