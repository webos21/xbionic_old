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

#include <ntdll.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
	int ret;
	int fd3 = __open("D:\\Temp\\xxx\\test.txt", O_RDWR, 00777);
	int npid = __fork();
	if (npid > 0) {
		char buf[16];
		printf("Parent Process!!! (child pid=%d)\n", npid);
		wait4(npid, &cret, 0, NULL);
		printf("result of child process = %d\n", cret);
		bzero(buf, sizeof(buf));
		ret = read(fd3, buf, 12);
		return 0;
	} else if (npid == 0) {
		char buf[16];
		printf("Child Process!!!\n");
		bzero(buf, sizeof(buf));
		ret = read(fd3, buf, 12);
		tsleep(3000);
		W_exit(ret); // test : process return -3
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

	char iobuf1[64];
	char iobuf2[64];

	struct iovec iov[2];

	int sock;
	struct sockaddr_in stSockAddr;

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
	ret = pwrite64(fd_f, "DDD", 3, 10);

	iov[0].iov_base = iobuf1;
	iov[0].iov_len = sizeof(iobuf1);
	iov[1].iov_base = iobuf2;
	iov[1].iov_len = sizeof(iobuf2);

	bzero(iobuf1, sizeof(iobuf1));
	bzero(iobuf2, sizeof(iobuf2));
	ret = lseek(fd_e, 0, SEEK_SET);
	ret = readv(fd_e, iov, 2);

	Wmemset(iobuf1, 'A', sizeof(iobuf1));
	Wmemset(iobuf2, 'B', sizeof(iobuf2));
	ret = writev(fd_e, iov, 2);

	ret = close(fd_e);
	ret = close(fd_d);
	ret = close(fd_f);
	ret = close(10);

	stSockAddr.sin_family = AF_INET;
	stSockAddr.sin_port = htons(1100);
	//inet_pton(AF_INET, "192.168.1.3", &stSockAddr.sin_addr);
	stSockAddr.sin_addr.s_addr = 0xCF313231;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ret = connect(sock, (struct sockaddr *)&stSockAddr, sizeof(stSockAddr));

	return 0;
}

int test_socket() {
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	return 0;
}

int test_vmem() {
	int fd = -1;
	int ret = 0;

	unsigned char vec[64];
	void *memAddr = NULL;
	size_t memLen = 3 * 1024 * 1024;

	void *newAddr = NULL;
	size_t newLen = 4 * 1024 * 1024;

//	fd = __open("D:\\Temp\\test_mmap.dat", O_RDWR, 00777);
//	memLen = lseek(fd, 0, SEEK_END);
	memAddr = __mmap2(memAddr, memLen, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	ret = madvise(memAddr, memLen, 0);
	ret = mlock(memAddr, 4096);
	ret = msync(memAddr, 4096, MS_SYNC|MS_INVALIDATE);
	ret = munlock(memAddr, 4096);
	newAddr = mremap(memAddr, memLen, newLen, 0);
	ret = mprotect(memAddr, memLen, PROT_EXEC);
	ret = mincore(memAddr, memLen, vec);
	ret = munmap(memAddr, memLen);
	ret = mincore(memAddr, memLen, vec);
	ret = close(fd);

	return ret;
}

int test_file_ctl() {
	int ret = 0;
	char buf[16];

	int fddir, fddir2;
	int fd3;
	int fd4;
	int fd5;
	int dfd6 = 6;
	int sock;
	int dfd8 = 8;

	off64_t longLen = 0;
	// FIXME
	//struct sockaddr_in stSockAddr;

	ntsc_t *ntfp = ntdll_getFP();

	fddir = __open("D:/Temp/xxx", O_CREAT|O_DIRECTORY|O_RDONLY, 00777);
	fd3 = __open("D:\\Temp\\xxx\\test.txt", O_RDWR, 00777);
	fd4 = __open("D:\\Temp\\test.txt", O_RDWR, 00777);
	fd5 = dup(fd3);
	dfd6 = dup2(fd4, dfd6);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	dfd8 = dup(sock);
	fddir2 = dup(fddir);

	bzero(buf, sizeof(buf));
	ret = read(fd3, buf, 12);
	close(fd3);
	ret = read(fd5, buf, 12);
	ret = read(fd3, buf, 12);
	ret = read(fd5, buf, 12);

	bzero(buf, sizeof(buf));
	ret = read(fd4, buf, 12);
	ret = read(dfd6, buf, 12);

	ret = fchmod(fd4, 00777);

	longLen = 8589934592LL;
	ret = ftruncate64(fd4, longLen);
	ret = ftruncate(fd4, 256);

	ret = flock(fd4, LOCK_EX);
	ret = flock(fd4, LOCK_SH);
	ret = flock(fd4, LOCK_UN);
	ret = flock(fd4, LOCK_UN);

	ret = flock(fddir2, LOCK_EX);
	ret = flock(fddir2, LOCK_SH);
	ret = flock(fddir2, LOCK_UN);
	ret = flock(fddir2, LOCK_UN);

	ret = flock(sock, LOCK_EX);
	ret = flock(sock, LOCK_UN);

	ret = flock(fd3, LOCK_UN);

	/*
	stSockAddr.sin_family = AF_INET;
	stSockAddr.sin_port = htons(1100);
	//inet_pton(AF_INET, "192.168.1.3", &stSockAddr.sin_addr);
	stSockAddr.sin_addr.s_addr = 0xCF313231;

	ret = connect(sock, (struct sockaddr *)&stSockAddr, sizeof(stSockAddr));
	ret = close(sock);
	ret = connect(dfd8, (struct sockaddr *)&stSockAddr, sizeof(stSockAddr));
	*/

	ret = close(fddir);
	ret = close(fddir2);
	ret = close(fd3);
	ret = close(fd4);
	ret = close(fd5);
	ret = close(dfd6);
	ret = close(sock);
	ret = close(dfd8);

	return ret;
}

int test_pipe() {
	int ret;
	int pipeFd[2];
	int pipeFd2[2];

	ret = pipe(pipeFd);
	ret = pipe2(pipeFd2, 0);

	ret = close(pipeFd[0]);
	ret = close(pipeFd[1]);
	ret = close(pipeFd2[0]);
	ret = close(pipeFd2[1]);

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
	//test_socket();
	//test_vmem();
	test_file_ctl();
	//test_pipe();

	return 0;
}
