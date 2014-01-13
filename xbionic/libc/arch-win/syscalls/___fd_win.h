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

#ifndef ____FD_WIN_H_
#define ____FD_WIN_H_

#include <ntdll.h>
#include <ntsock.h>

typedef enum _e_fd_type {
	XB_FD_TYPE_NOTUSED = 0,
	XB_FD_TYPE_FILE    = 1,
	XB_FD_TYPE_DIR     = 2,
	XB_FD_TYPE_SOCK    = 3,
	XB_FD_TYPE_PIPE    = 4
} xb_fd_type_e;

typedef struct _st_fd {
	int             fdtype;
	union _u_desc {
		struct _st_file {
			HANDLE  fd;
			int     flag;
			int     mode;
			char   *path;
		} f;
		struct _st_dir {
			HANDLE  fd;
			int     flag;
			int     mode;
			char   *path;
		} d;
		struct _st_sock {
			SOCKET  fd;
			int     family;
			int     type;
			INT_PTR proto;
		} s;
	} desc;
} xb_fd_t;

int      xb_fd_count();
xb_fd_t *xb_fd_get(int idx);

int      xb_fd_open(xb_fd_t *fd);
int      xb_fd_open_idx(xb_fd_t *fd, int idx);
int      xb_fd_close(int idx);

#endif //____FD_WIN_H_
