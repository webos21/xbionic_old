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
#include <errno.h>

#include <sys/capability.h>

// set capabilities of thread(s)
// ref {
//     http://man7.org/linux/man-pages/man2/capset.2.html
// }
int capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("capset() is called, but it is not implemented!!!\n");
	errno = 0;
	return 0;
}
