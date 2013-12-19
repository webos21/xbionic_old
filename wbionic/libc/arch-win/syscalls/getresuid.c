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

#include <errno.h>
#include <ntdll.h>

#define __UID    64

// Get real GID
//int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int getresuid(int *ruid, int *euid, int *suid) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("getresuid() is called, but it is not implemented!!!\n");
	errno = 0;
	(*ruid) = __UID;
	(*euid) = __UID;
	(*suid) = __UID;
	return 0;
}
