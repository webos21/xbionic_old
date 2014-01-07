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

// fill memory with a constant byte
// ref {
//     http://man7.org/linux/man-pages/man3/memset.3.html
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff561870(v=vs.85).aspx
// }

// modified by cmjo for VS2010 {{{
// - The name is same as Windows API
#ifdef _MSC_VER
void *Wmemset(void *s, int c, size_t n) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlFillMemory(s, n, c);
	return s;
}
#else  // !_MSC_VER
void *memset(void *s, int c, size_t n) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlFillMemory(s, n, c);
	return s;
}
#endif // _MSC_VER
// }}}
