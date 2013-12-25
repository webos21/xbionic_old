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

#ifndef _TEST_H_
#define _TEST_H_ 1

#include <ntdll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>

////////////////////////
// String Functions
////////////////////////

void bcopy(const void *src, void *dest, size_t n);
void bzero(void *s, size_t n);
int Wmemcmp(const void *s1, const void *s2, size_t n); // change the name for avoiding the duplication
void *Wmemcpy(void *dest, const void *src, size_t n);  // change the name for avoiding the duplication
void *memmove(void *dest, const void *src, size_t n);
void *Wmemset(void *s, int c, size_t n);               // change the name for avoiding the duplication


////////////////////////
// Bionic Functions
////////////////////////

void _exit_with_stack_teardown(void *stackBase, int stackSize, int *retCode);

int  __pthread_clone(void* (*fn)(void*), void* tls, int flags, void* arg);
int  __bionic_clone(unsigned long clone_flags,
	void*         newsp,
	int           *parent_tidptr,
	void          *new_tls,
	int           *child_tidptr,
	int           (*fn)(void *),
	void          *arg);

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout);
int __futex_wake(volatile void *ftx, int count);
int __futex_syscall3(volatile void *ftx, int op, int count);
int __futex_syscall4(volatile void *ftx, int op, int val, const struct timespec *timeout);

int syscall(int number, ...);

int vfork(void);


////////////////////////
// System-call Functions
////////////////////////

void W_exit(int status);
void _exit_thread(int status);

int __fork(void);

pid_t _waitpid(pid_t pid, int *status, int options); // Not Used by wait.cpp
int __waitid(idtype_t which, id_t id, siginfo_t* info, int options, struct rusage* ru);
pid_t wait4(pid_t pid, int *status, int options, struct rusage *ru);

int execve(const char *filename, char *const argv[], char *const envp[]);

int __setuid(uid_t uid);

pid_t gettid(void);

pid_t getppid(void);

int kill(pid_t pid, int sig);

#endif // _TEST_H_
