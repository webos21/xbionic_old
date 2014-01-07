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

#include <linux/prctl.h>

// operations on a process
// ref {
//     http://man7.org/linux/man-pages/man2/prctl.2.html
// }
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_DbgPrint("prctl() is called, but it is not implemented!!!\n");

	switch (option) {
	case PR_CAPBSET_READ:
	case PR_CAPBSET_DROP:
	case PR_SET_CHILD_SUBREAPER:
	case PR_GET_CHILD_SUBREAPER:
	case PR_SET_DUMPABLE:
	case PR_GET_DUMPABLE:
	case PR_SET_ENDIAN:
		switch (arg2) {
		case PR_ENDIAN_BIG:
		case PR_ENDIAN_LITTLE:
		case PR_ENDIAN_PPC_LITTLE:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_ENDIAN:
	case PR_SET_FPEMU:
		switch (arg2) {
		case PR_FPEMU_NOPRINT:
		case PR_FPEMU_SIGFPE:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_FPEMU:
	case PR_SET_FPEXC:
		switch (arg2) {
		case PR_FP_EXC_SW_ENABLE:
		case PR_FP_EXC_DIV:
		case PR_FP_EXC_OVF:
		case PR_FP_EXC_UND:
		case PR_FP_EXC_INV:
		case PR_FP_EXC_DISABLED:
		case PR_FP_EXC_NONRECOV:
		case PR_FP_EXC_ASYNC:
		case PR_FP_EXC_PRECISE:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_FPEXC:
	case PR_SET_KEEPCAPS:
	case PR_GET_KEEPCAPS:
	case PR_SET_NAME:
	case PR_GET_NAME:
	case PR_SET_NO_NEW_PRIVS:
	case PR_GET_NO_NEW_PRIVS:
	case PR_SET_PDEATHSIG:
	case PR_GET_PDEATHSIG:
	case PR_SET_PTRACER:
		if (arg2 != 0 && arg2 != PR_SET_PTRACER_ANY) {
			errno = EINVAL;
			return -1;
		}
	case PR_SET_SECCOMP:
	case PR_GET_SECCOMP:
	case PR_SET_SECUREBITS:
	case PR_GET_SECUREBITS:
	case PR_GET_TID_ADDRESS:
	case PR_SET_TIMERSLACK:
	case PR_GET_TIMERSLACK:
	case PR_SET_TIMING:
		switch (arg2) {
		case PR_TIMING_STATISTICAL:
		case PR_TIMING_TIMESTAMP:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_TIMING:
	case PR_TASK_PERF_EVENTS_DISABLE:
	case PR_TASK_PERF_EVENTS_ENABLE:
	case PR_SET_TSC:
		switch (arg2) {
		case PR_TSC_ENABLE:
		case PR_TSC_SIGSEGV:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_TSC:
	case PR_SET_UNALIGN:
		switch (arg2) {
		case PR_UNALIGN_NOPRINT:
		case PR_UNALIGN_SIGBUS:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_GET_UNALIGN:
	case PR_MCE_KILL:
		switch (arg2) {
		case PR_MCE_KILL_CLEAR:
		case PR_MCE_KILL_SET:
			switch (arg3) {
				case PR_MCE_KILL_EARLY:
				case PR_MCE_KILL_LATE:
				case PR_MCE_KILL_DEFAULT:
					break;
				default:
					errno = EINVAL;
					return -1;
			}
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	case PR_MCE_KILL_GET:
	case PR_SET_MM:
		if (arg4 != 0 || arg5 != 0) {
			errno = EINVAL;
			return -1;
		}
		switch (arg2) {
		case PR_SET_MM_START_CODE:
		case PR_SET_MM_END_CODE:
		case PR_SET_MM_START_DATA:
		case PR_SET_MM_END_DATA:
		case PR_SET_MM_START_STACK:
		case PR_SET_MM_START_BRK:
		case PR_SET_MM_BRK:
			break;
		default:
			errno = EINVAL;
			return -1;
		}
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	errno = 0;
	return 0;
}
