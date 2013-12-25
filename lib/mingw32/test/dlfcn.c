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

#include <dlfcn.h>

#define __in
#define __out_opt

#define FAR

#define WINBASEAPI
#define WINAPI      __stdcall

typedef struct _HINSTANCE {
	int unused;
} *HINSTANCE;
typedef HINSTANCE   HMODULE;

typedef int         BOOL;
typedef int        *(FAR WINAPI *FARPROC)();
typedef const char *LPCSTR, *PCSTR;

WINBASEAPI
	__out_opt
	HMODULE
	WINAPI
	LoadLibraryA(
	__in LPCSTR lpLibFileName
	);

WINBASEAPI
	BOOL
	WINAPI
	FreeLibrary (
	__in HMODULE hLibModule
	);

WINBASEAPI
	FARPROC
	WINAPI
	GetProcAddress (
	__in HMODULE hModule,
	__in LPCSTR lpProcName
	);


void *dlopen(const char*  filename, int flag) {
	return LoadLibraryA(filename);
}

int dlclose(void*  handle) {
	return FreeLibrary((HMODULE)handle);
}

const char *dlerror(void) {
	return "";
}

void *dlsym(void* handle, const char *symbol) {
	return GetProcAddress((HMODULE)handle, symbol);
}

int dladdr(const void * addr, Dl_info *info) {
	return 0;
}
