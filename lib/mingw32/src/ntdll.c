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
#include <dlfcn.h>

static void *_g_ntdll = NULL;
static ntsc_t _g_ntfp;

ntsc_t *ntdll_getFP() {
	if (_g_ntdll == NULL ) {
		// load the [ntdll.dll]
		_g_ntdll = dlopen("ntdll.dll", 0);

		// mapping the [ntdll.dll] APIs
		_g_ntfp.FP_RtlExitUserProcess = dlsym(_g_ntdll, "RtlExitUserProcess");

		_g_ntfp.FP_RtlExitUserThread = dlsym(_g_ntdll, "RtlExitUserThread");

		_g_ntfp.FP_RtlCreateProcessParameters = dlsym(_g_ntdll,
				"RtlCreateProcessParameters");
		_g_ntfp.FP_RtlDestroyProcessParameters = dlsym(_g_ntdll,
				"RtlDestroyProcessParameters");
		_g_ntfp.FP_RtlCreateUserProcess = dlsym(_g_ntdll,
				"RtlCreateUserProcess");

		_g_ntfp.FP_RtlCloneUserProcess = dlsym(_g_ntdll, "RtlCloneUserProcess");
		_g_ntfp.FP_RtlUpdateClonedCriticalSection = dlsym(_g_ntdll,
				"RtlUpdateClonedCriticalSection");
		_g_ntfp.FP_RtlUpdateClonedSRWLock = dlsym(_g_ntdll,
				"RtlUpdateClonedSRWLock");
	}
	return &_g_ntfp;
}
