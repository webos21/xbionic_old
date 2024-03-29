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

// exit with cleaning the virtual memory
// ref {
//     http://linux.die.net/man/2/munmap
//     http://linux.die.net/man/2/_exit
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff556528(v=vs.85).aspx
//     http://msdn.microsoft.com/en-us/library/windows/hardware/ff566460(v=vs.85).aspx
// }
void _exit_with_stack_teardown(void *stackBase, int stackSize, int *retCode) {
	int status = (*retCode);
	ntsc_t *ntfp = ntdll_getFP();

	ntfp->FP_NtFreeVirtualMemory(XbNtCurrentProcess(), &stackBase, (PSIZE_T)&stackSize, 0);
	errno = status;
	ntfp->FP_RtlExitUserThread(status);
}
