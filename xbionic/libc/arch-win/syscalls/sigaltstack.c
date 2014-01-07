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

#include <signal.h>

// set and/or get signal stack context
//
// NOTE)
//   The most common usage of an alternate signal stack is to handle the
//   SIGSEGV signal that is generated if the space available for the
//   normal process stack is exhausted
//
// ref {
//     http://man7.org/linux/man-pages/man2/sigaltstack.2.html
//     http://man7.org/linux/man-pages/man2/sigaction.2.html
// }
int sigaltstack(const stack_t *ss, stack_t *oss) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("sigaltstack() is called, but it is not implemented!!!\n");
	errno = 0;
	return 0;
}
