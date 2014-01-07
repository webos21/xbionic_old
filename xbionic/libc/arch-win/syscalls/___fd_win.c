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

#include "___fd_win.h"

#include <errno.h>
#include <string.h>

// ----------------------------------------------
// Global Variables
// ----------------------------------------------

#define XCFG_FD_MAX 4096

// ----------------------------------------------
// Global Variables
// ----------------------------------------------

static xb_fd_t _g_fds[XCFG_FD_MAX];
static BOOLEAN _g_fd_init = FALSE;
static int _g_fd_total = 0;
static int _g_fd_last = 0;

// ----------------------------------------------
// Inner Functions
// ----------------------------------------------

static void xg_fd_init() {
	if (!_g_fd_init) {
		ntsc_t *ntfp = ntdll_getFP();
		ntfp->FP_RtlZeroMemory(_g_fds, sizeof(_g_fds));

		// STDIN
		_g_fds[0].fdtype = XB_FD_TYPE_FILE;
		_g_fds[0].desc.f.fd = NULL;
		_g_fds[0].desc.f.flag = FILE_GENERIC_READ;
		_g_fds[0].desc.f.mode = 0x400;
		_g_fds[0].desc.f.path = NULL;

		// STDOUT
		_g_fds[1].fdtype = XB_FD_TYPE_FILE;
		_g_fds[1].desc.f.fd = NULL;
		_g_fds[1].desc.f.flag = FILE_GENERIC_WRITE;
		_g_fds[1].desc.f.mode = 0x200;
		_g_fds[1].desc.f.path = NULL;

		// STDERR
		_g_fds[2].fdtype = XB_FD_TYPE_FILE;
		_g_fds[2].desc.f.fd = NULL;
		_g_fds[2].desc.f.flag = FILE_GENERIC_WRITE;
		_g_fds[2].desc.f.mode = 0x200;
		_g_fds[2].desc.f.path = NULL;

		_g_fd_total = 3;
		_g_fd_last = 2;
		_g_fd_init = TRUE;
	}
}

// ----------------------------------------------
// XG Functions
// ----------------------------------------------

int xb_fd_count() {
	return _g_fd_total;
}

xb_fd_t *xb_fd_get(int idx) {
	if (idx < 0 || idx >= XCFG_FD_MAX) {
		errno = EBADF;
		return NULL;
	}
	if (!_g_fd_init) {
		xg_fd_init();
	}
	return &(_g_fds[idx]);
}

int xb_fd_open(xb_fd_t *fd) {
	int i;
	ntsc_t *ntfp = ntdll_getFP();

	if (!_g_fd_init) {
		xg_fd_init();
	}
	if (fd == NULL || (fd->fdtype < XB_FD_TYPE_FILE && fd->fdtype > XB_FD_TYPE_PIPE)) {
		// log_error(XDLOG, "idx=%d\n", idx);
		errno = EINVAL;
		return -1;
	}

	for (i = _g_fd_last; i < XCFG_FD_MAX; i++) {
		if (_g_fds[i].fdtype == XB_FD_TYPE_NOTUSED) {
			xb_fd_t *dest = &(_g_fds[i]);
			ntfp->FP_RtlCopyMemory(dest, fd, sizeof(xb_fd_t));
			if (fd->fdtype == XB_FD_TYPE_FILE && fd->desc.f.path != NULL) {
				dest->desc.f.path = (char *)ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, strlen(fd->desc.f.path)+1);
				strcpy(dest->desc.f.path, fd->desc.f.path);
			}
			if (fd->fdtype == XB_FD_TYPE_DIR && fd->desc.d.path != NULL) {
				dest->desc.d.path = (char *)ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, strlen(fd->desc.d.path)+1);
				strcpy(dest->desc.d.path, fd->desc.d.path);
			}
			_g_fd_last = i;
			_g_fd_total++;
			// if (_g_fd_total > (XCFG_FD_MAX - 10)) {
			// 	log_warn(XDLOG, "FD-Total is very close to Limit(4096)\n");
			// }
			return i;
		}
	}

	if (_g_fd_total < XCFG_FD_MAX) {
		_g_fd_last = 0;
	}

	for (i = _g_fd_last; i < XCFG_FD_MAX; i++) {
		if (_g_fds[i].fdtype == XB_FD_TYPE_NOTUSED) {
			xb_fd_t *dest = &(_g_fds[i]);
			ntfp->FP_RtlCopyMemory(dest, fd, sizeof(xb_fd_t));
			if (fd->fdtype == XB_FD_TYPE_FILE && fd->desc.f.path != NULL) {
				dest->desc.f.path = (char *)ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, strlen(fd->desc.f.path)+1);
				strcpy(dest->desc.f.path, fd->desc.f.path);
			}
			if (fd->fdtype == XB_FD_TYPE_DIR && fd->desc.d.path != NULL) {
				dest->desc.d.path = (char *)ntfp->FP_RtlAllocateHeap(XbRtlGetProcessHeap(ntfp), 0, strlen(fd->desc.d.path)+1);
				strcpy(dest->desc.d.path, fd->desc.d.path);
			}
			_g_fd_last = i;
			_g_fd_total++;
			// if (_g_fd_total > (XCFG_FD_MAX - 10)) {
			// 	log_warn(XDLOG, "FD-Total is very close to Limit(4096)\n");
			// }
			return i;
		}
	}

	// log_error(XDLOG, "Cannot find free-fd!!!\n");
	errno = EMFILE;
	return -1;
}

int xb_fd_close(int idx) {
	ntsc_t *ntfp = ntdll_getFP();

	if (idx < 0 || idx >= XCFG_FD_MAX) {
		// log_error(XDLOG, "idx=%d\n", idx);
		errno = EINVAL;
		return -1;
	}

	if (_g_fds[idx].fdtype == XB_FD_TYPE_FILE && _g_fds[idx].desc.f.path != NULL) {
		ntfp->FP_RtlFreeHeap(XbRtlGetProcessHeap(ntfp), 0, _g_fds[idx].desc.f.path);
		_g_fds[idx].desc.f.path = NULL;
	}
	if (_g_fds[idx].fdtype == XB_FD_TYPE_DIR && _g_fds[idx].desc.d.path != NULL) {
		ntfp->FP_RtlFreeHeap(XbRtlGetProcessHeap(ntfp), 0, _g_fds[idx].desc.d.path);
		_g_fds[idx].desc.d.path = NULL;
	}
	ntfp->FP_RtlZeroMemory(&(_g_fds[idx]), sizeof(xb_fd_t));
	_g_fd_total--;

	return 0;
}
