/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
/* These are stubs for functions that are actually defined
 * in the dynamic linker (dlfcn.c), and hijacked at runtime.
 */

// modified by cmjo for Windows
// - The command "ld" of MinGW-Builds does not process the "-dynamic-linker" option.
// - So, we have to implement the function directly here!!!
#ifdef _WIN32

#define __in
#define __out_opt

#define FAR

#define WINBASEAPI
#define WINAPI      __attribute__((__stdcall__))

typedef struct _HINSTANCE {
	int unused;
}*HINSTANCE;
typedef HINSTANCE HMODULE;

typedef int BOOL;
typedef int *(FAR WINAPI *FARPROC)();
typedef const char *LPCSTR, *PCSTR;
typedef unsigned long DWORD;
typedef void FAR *LPVOID;

WINBASEAPI
__out_opt
HMODULE
WINAPI
LoadLibraryExA(LPCSTR lpLibFileName, void *hFile, DWORD dwFlags);

WINBASEAPI
BOOL
WINAPI
FreeLibrary( __in HMODULE hLibModule);

WINBASEAPI
FARPROC
WINAPI
GetProcAddress( __in HMODULE hModule, __in LPCSTR lpProcName);

void *dlopen(const char* filename, int flag) {
	return LoadLibraryExA(filename, (void *)(0), flag);
}

const char *dlerror(void) {
	return "";
}

void *dlsym(void* handle, const char *symbol) {
	return GetProcAddress((HMODULE) handle, symbol);
}

int dladdr(const void * addr, Dl_info *info) {
	return 0;
}

int dlclose(void* handle) {
	return FreeLibrary((HMODULE) handle);
}

void android_update_LD_LIBRARY_PATH(const char* ld_library_path) {

}

// only for MINGW
void __cxa_finalize(void *dso) {
}

int __cxa_atexit(void (*func)(void *), void *arg, void *dso) {
	return 0;
}

#else // !_WIN32

void *dlopen(const char *filename, int flag) { return 0; }
const char *dlerror(void) { return 0; }
void *dlsym(void *handle, const char *symbol) { return 0; }
int dladdr(const void *addr, Dl_info *info) { return 0; }
int dlclose(void *handle) { return 0; }

void android_update_LD_LIBRARY_PATH(const char* ld_library_path) { }
#endif // _WIN32

#if defined(__arm__)

void *dl_unwind_find_exidx(void *pc, int *pcount) { return 0; }

#elif defined(__i386__) || defined(_WIN64) || defined(__mips__)

/* we munge the cb definition so we don't have to include any headers here.
 * It won't affect anything since these are just symbols anyway */
int dl_iterate_phdr(int (*cb)(void *info, void *size, void *data), void *data) {
	return 0;
}

#else
#error Unsupported architecture. Only mips, arm and x86 are supported.
#endif
