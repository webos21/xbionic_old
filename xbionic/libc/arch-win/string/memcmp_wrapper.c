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

// modified by cmjo for VS2010 {{{
#ifdef _MSC_VER
int Wmemcmp(const void *s1, const void *s2, size_t n) {
	ntsc_t *ntfp = ntdll_getFP();
	return (int) ntfp->FP_RtlCompareMemory(s1, s2, n);
}
#else  // !_MSC_VER
int memcmp(const void *s1, const void *s2, size_t n) {
	ntsc_t *ntfp = ntdll_getFP();
	return (int) ntfp->FP_RtlCompareMemory(s1, s2, n);
}
#endif // _MSC_VER
// }}}
