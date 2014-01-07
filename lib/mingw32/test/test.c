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

#include "test.h"

extern int printf(const char *, ...);

void test_windows(void) {
//#include <windows.h>
//	CONTEXT x;
}

void tsleep(int msec) {
	LARGE_INTEGER x;
	ntsc_t *ntfp = ntdll_getFP();
	x.QuadPart = msec * -10000;
	ntfp->FP_NtDelayExecution(FALSE, &x);
}

int test_peb() {
	ntsc_t *ntfp = ntdll_getFP();
	PPEB_VISTA_7 x = ntfp->FP_RtlGetCurrentPeb();
	return 0;
}

int test_teb() {
	PTEB_7 x = XbNtCurrentTeb();
	return 0;
}

int test_ctx() {
	CONTEXT ctx;
	
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlCaptureContext(&ctx);
	return 0;
}

int test_raise_exception() {
	EXCEPTION_RECORD er;
	ntsc_t *ntfp = ntdll_getFP();

	ntfp->FP_RtlZeroMemory(&er, sizeof(er));
	er.ExceptionCode = -1;
	er.ExceptionFlags = 0;
	er.ExceptionRecord = NULL;
	er.ExceptionAddress = NULL;
	er.NumberParameters = 0;
	ntfp->FP_RtlRaiseException(&er);
	return 0;
}

int test_raise_status() {
	ntsc_t *ntfp = ntdll_getFP();
	ntfp->FP_RtlRaiseStatus(STATUS_PROCESS_NOT_IN_JOB);
	return 0;
}

int test_fork() {
	int cret = 0;
	int npid = __fork();
	if (npid > 0) {
		printf("Parent Process!!! (child pid=%d)\n", npid);
		wait4(npid, &cret, 0, NULL);
		printf("result of child process = %d\n", cret);
		return 0;
	} else if (npid == 0) {
		printf("Child Process!!!\n");
		tsleep(3000);
		W_exit(-3); // test : process return -3
		return 0;   // for compiler's happyness
	} else {
		printf("error!!!!!!!!!\n");
		return npid;
	}
}

int test_exit_with_stack_teardown() {
	int status = 0x3;
	_exit_with_stack_teardown(NULL, 0, &status);
	return 0;
}

static void *test_pthread(void *args) {
	int x = (int) args;
	printf("PThread - %d\n", x);
	return NULL;
}

static int test_bthread(void *args) {
	int x = (int) args;
	printf("BThread - %d\n", x);
	return x;
}

void __bionic_clone_entry( int (*fn)(void *), void *arg ) {
	int ret = (*fn)(arg);
	_exit_thread(ret);
}

int test__pthread_clone() {
	int x = 333;
	__pthread_clone(&test_pthread, NULL, 0, (void*)x);
	return 0;
}

int test__bionic_clone() {
	int x = 333;
	__bionic_clone(0, NULL, NULL, NULL, NULL, &test_bthread, (void*)x);
	return 0;
}

int test_execve() {
	int ret;
	char *const argv[] = {"C:\\Windows\\System32\\cmd.exe", "/?", NULL};
	char *const envp[] = {"TEST=1", "LD_DIR=2", NULL};
	ret = execve("C:\\Windows\\System32\\cmd.exe", argv, envp);
	return ret;
}

int test_gettid() {
	int tid = gettid();
	printf("tid = %d\n", tid);
	return tid;
}

int test_getppid() {
	pid_t pid = 0;
	pid_t ppid = 0;
	
	pid = getpid();
	ppid = getppid();
	printf("pid = %d / parent pid = %d\n", pid, ppid);
	return pid;
}

int test_set_thread_area() {
	int x = 3;
	__set_thread_area((void *)&x);
	return 0;
}

int test_io() {
	loff_t pos;
	ssize_t ret;
	int fd_f, fd_d, fd_e;
	char buf[16];

	fd_f = __open("D:/Temp/test.txt", O_CREAT|O_RDWR|O_TRUNC, 00777);
	fd_d = __open("D:/Temp/xxx", O_CREAT|O_DIRECTORY|O_RDONLY, 00777);
	fd_e = __openat(fd_d, "test.txt", O_RDWR, 00777);
	
	ret = __llseek(fd_e, 0, 0, &pos, SEEK_END);
	ret = lseek(fd_e, 0, SEEK_END);
	bzero(buf, sizeof(buf));
	ret = read(fd_e, buf, 12);
	bzero(buf, sizeof(buf));
	ret = read(fd_e, buf, 12);
	ret = lseek(fd_e, -12, SEEK_CUR);
	bzero(buf, sizeof(buf));
	ret = read(fd_e, buf, 12);
	ret = lseek(fd_e, 0, SEEK_CUR);
	bzero(buf, sizeof(buf));
	ret = pread64(fd_e, buf, 12, 0);
	bzero(buf, sizeof(buf));
	ret = read(fd_e, buf, 12);
	ret = write(fd_e, "CCC", 3);
	ret = lseek(fd_e, 0, SEEK_SET);
	ret = pwrite64(fd_f, "DDD", 3, 10);
	ret = close(fd_e);
	ret = close(fd_d);
	ret = close(fd_f);
	ret = close(10);
	return 0;
}

int test_vmem() {
	int fd = -1;
	int ret = 0;

	void *memAddr = NULL;
	size_t memLen = 4 * 1024 * 1024;

	void *newAddr = NULL;
	size_t newLen = 8 * 1024 * 1024;

	fd = __open("D:\\Temp\\test_mmap.dat", O_RDWR, 00777);
	memLen = lseek(fd, 0, SEEK_END);
	memAddr = __mmap2(memAddr, memLen, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	ret = madvise(memAddr, memLen, 0);
	ret = mlock(memAddr, 4096);
	ret = msync(memAddr, 4096, MS_SYNC|MS_INVALIDATE);
	ret = munlock(memAddr, 4096);
	//newAddr = mremap(memAddr, memLen, newLen, 0);
	ret = munmap(memAddr, memLen);
	ret = close(fd);

	return ret;
}

int main(int argc, char *argv[]) {
	int i = 0;
	int x = 0;

	//test_peb();
	//test_teb();
	//test_ctx();
	//test_raise_exception();
	//test_raise_status();
	//test_fork();
	//test__pthread_clone();
	//test__bionic_clone();
	//Sleep(1000);
	//test_execve();
	//test_gettid();
	//test_getppid();
	//test_set_thread_area();
	//test_io();
	test_vmem();

	return 0;
}
