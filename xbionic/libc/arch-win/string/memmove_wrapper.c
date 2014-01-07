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
#include <sys/types.h>

// copy memory area (memory area may overlap)
// ref {
//     http://man7.org/linux/man-pages/man3/memmove.3.html
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff562030(v=vs.85).aspx
// }
void *memmove(void *dest, const void *src, size_t n) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlMoveMemory(dest, (PVOID)src, n);
	return dest;
}
