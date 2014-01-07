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

// copy memory area 
// ref {
//     http://man7.org/linux/man-pages/man3/memcpy.3.html
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff561808(v=vs.85).aspx
// }

// modified by cmjo for VS2010 {{{
// - The name is same as Windows API
#ifdef _MSC_VER
void *Wmemcpy(void *dest, const void *src, size_t n){
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlCopyMemory(dest, (const PVOID)src, n);
	return dest;
}
#else  // !_MSC_VER
void *memcpy(void *dest, const void *src, size_t n){
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlCopyMemory(dest, (const PVOID)src, n);
	return dest;
}
#endif // _MSC_VER
// }}}
