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

#include <ntsock.h>

#include <errno.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include "___fd_win.h"

static int _xwsa_cvt_domain(int domain);
static int _xwsa_cvt_type(int type);
static int _xwsa_cvt_protocol(int protocol);


// create an endpoint for communication  
// ref {
//     http://linux.die.net/man/2/socket
// }
int socket(int domain, int type, int protocol) {
	int xw_domain;
	int xw_type;
	int xw_proto;

	xb_fd_t fdesc;

	ntsock_t *wsfp = ntsock_getFP();

	xw_domain = _xwsa_cvt_domain(domain);
	xw_type = _xwsa_cvt_type(type);
	xw_proto = _xwsa_cvt_protocol(protocol);

	if (xw_domain < 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (xw_type < 0) {
		errno = EINVAL;
		return -1;
	}
	if (xw_proto < 0) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	fdesc.fdtype = XB_FD_TYPE_SOCK;
	fdesc.desc.s.family = domain;
	fdesc.desc.s.type = type;
	fdesc.desc.s.proto = protocol;

	fdesc.desc.s.fd = wsfp->FP_socket(xw_domain, xw_type, xw_proto);
	if (fdesc.desc.s.fd == INVALID_SOCKET) {
		int err = wsfp->FP_WSAGetLastError();
		switch (err) {
		case WSANOTINITIALISED:
		case WSAENETDOWN:
			errno = EACCES;
			return -1;
		case WSAEAFNOSUPPORT:
			errno = EAFNOSUPPORT;
			return -1;
		case WSAEPROTONOSUPPORT:
			errno = EPROTONOSUPPORT;
			return -1;
		case WSAEINPROGRESS:
			errno = EINPROGRESS;
			return -1;
		case WSAEMFILE:
			errno = EMFILE;
			return -1;
		case WSAENOBUFS:
			errno = ENOBUFS;
			return -1;
		case WSAEINVAL:
		case WSAEINVALIDPROVIDER:
		case WSAEINVALIDPROCTABLE:
		case WSAEPROTOTYPE:
		case WSAEPROVIDERFAILEDINIT:
		case WSAESOCKTNOSUPPORT:
		default:
			errno = EINVAL;
			return -1;
		}
	} else {
		errno = 0;
		return xb_fd_open(&fdesc);
	}
}

static int _xwsa_cvt_domain(int domain) {
	switch (domain) {
	case AF_INET:
		return XWSA_AF_INET;
	case AF_IPX:
		return XWSA_AF_IPX;
	case AF_APPLETALK:
		return XWSA_AF_APPLETALK;
//	case AF_NETBIOS:
//		return XWSA_AF_NETBIOS;
	case AF_INET6:
		return XWSA_AF_INET6;
	case AF_IRDA:
		return XWSA_AF_IRDA;
	case AF_UNSPEC:
		return XWSA_AF_UNSPEC;
	default:
		return -1;
	}
}

static int _xwsa_cvt_type(int type) {
	switch (type) {
	case SOCK_STREAM:
		return XWSA_SOCK_STREAM;
	case SOCK_DGRAM:
		return XWSA_SOCK_DGRAM;
	case SOCK_RAW:
		return XWSA_SOCK_RAW;
	case SOCK_RDM:
		return XWSA_SOCK_RDM;
	case SOCK_SEQPACKET:
		return XWSA_SOCK_SEQPACKET;
	default:
		return -1;
	}
}

static int _xwsa_cvt_protocol(int protocol) {
	switch (protocol) {
	case IPPROTO_ICMP:
		return XWSA_IPPROTO_ICMP;
	case IPPROTO_IGMP:
		return XWSA_IPPROTO_IGMP;
//	case BTHPROTO_RFCOMM:
//		return XWSA_BTHPROTO_RFCOMM;
	case IPPROTO_TCP:
		return XWSA_IPPROTO_TCP;
	case IPPROTO_UDP:
		return XWSA_IPPROTO_UDP;
	case IPPROTO_ICMPV6:
		return XWSA_IPPROTO_ICMPV6;
//	case IPPROTO_RM:
//		return XWSA_IPPROTO_RM;
	default:
		return -1;
	}
}
