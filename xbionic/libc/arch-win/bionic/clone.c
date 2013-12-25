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

// int  __pthread_clone(void* (*fn)(void*), void* tls, int flags, void* arg);
int  __pthread_clone(void* (*fn)(void*), void* tls, int flags, void* arg)
{
	HANDLE hThd;
	CLIENT_ID cid;
	NTSTATUS status;
	ntsc_t *ntfp = ntdll_getFP();

	status = ntfp->FP_RtlCreateUserThread(XbNtCurrentProcess(),NULL,FALSE,0,0,0,fn,arg,&hThd,&cid);
	if (status == 0) {
		return (int) cid.UniqueThread;
	} else {
		errno = status;
		return -1;
	}
}

typedef struct ___bionic_clone_args {
	int (*fn)(void *);
	void *args;
} __bionic_clone_args;

extern void __bionic_clone_entry( int (*fn)(void *), void *arg );

static void *__bionic_clone_fn(void *args) {
	__bionic_clone_args *xargs = (__bionic_clone_args *)args;

	int (*rfunc)(void *) = xargs->fn;
	void *rargs = xargs->args;

	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlFreeHeap(XbRtlGetProcessHeap(ntfp), 0, args);

	__bionic_clone_entry(rfunc, rargs);
	return NULL;
}

/*
 * int  __bionic_clone(unsigned long clone_flags,
 *                     void*         newsp,
 *                     int           *parent_tidptr,
 *                     void          *new_tls,
 *                     int           *child_tidptr,
 *                     int           (*fn)(void *),
 *                     void          *arg);
 */
int  __bionic_clone(unsigned long clone_flags,
	void*         newsp,
	int           *parent_tidptr,
	void          *new_tls,
	int           *child_tidptr,
	int           (*fn)(void *),
	void          *arg)
{
	HANDLE hThd;
	CLIENT_ID cid;
	NTSTATUS status;

	__bionic_clone_args *xargs;

	ntsc_t *ntfp = ntdll_getFP();

	xargs = ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, sizeof(__bionic_clone_args));
	xargs->fn = fn;
	xargs->args = arg;

	status = ntfp->FP_RtlCreateUserThread(XbNtCurrentProcess(),NULL,FALSE,0,0,0,&__bionic_clone_fn,xargs,&hThd,&cid);
	if (status == 0) {
		return (int) cid.UniqueThread;
	} else {
		errno = status;
		return -1;
	}
}
