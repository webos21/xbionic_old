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
#include <dlfcn.h>

//////////////////////////////////////////
// Forward Declarations (compiler happy)
//////////////////////////////////////////

extern int printf(const char *, ...);


//////////////////////////////////////////
// Static Variables
//////////////////////////////////////////

static void *_g_ws2_32 = NULL;
static ntsock_t _g_sockfp;
static WSADATA _g_wsaData;


//////////////////////////////////////////
// Interface Functions
//////////////////////////////////////////

ntsock_t *ntsock_getFP() {
	if (NULL == _g_ws2_32) {
		WORD reqVer = MAKEWORD(2, 2);

		// load the [ntdll.dll]
		_g_ws2_32 = dlopen("ws2_32.dll", 0);
		if (NULL == _g_ws2_32) {
			printf("cannot load [ws2_32.dll]");
			return NULL;
		}

		// mapping the [ws2_32.dll] APIs
		_g_sockfp.FP_WSAStartup = dlsym(_g_ws2_32, "WSAStartup");
		_g_sockfp.FP_WSACleanup = dlsym(_g_ws2_32, "WSACleanup");
		_g_sockfp.FP_WSAGetLastError = dlsym(_g_ws2_32, "WSAGetLastError");
		_g_sockfp.FP_WSADuplicateSocketA = dlsym(_g_ws2_32, "WSADuplicateSocketA");
		_g_sockfp.FP_WSASocketA = dlsym(_g_ws2_32, "WSASocketA");

		_g_sockfp.FP_socket = dlsym(_g_ws2_32, "socket");
		_g_sockfp.FP_closesocket = dlsym(_g_ws2_32, "closesocket");
		_g_sockfp.FP_connect = dlsym(_g_ws2_32, "connect");
		_g_sockfp.FP_recv = dlsym(_g_ws2_32, "recv");
		_g_sockfp.FP_send = dlsym(_g_ws2_32, "send");

		// Startup Windows Socket API
		_g_sockfp.FP_WSAStartup(reqVer, &_g_wsaData);
	}
	return &_g_sockfp;
}
