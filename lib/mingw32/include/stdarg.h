/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef STDARG_H
#define STDARG_H

/* We use -nostdinc -ffreestanding to keep host system include files
 * from contaminating our build.
 * Unfortunately this also gets us rid of the _compiler_ includes, like
 * stdarg.h. To work around the issue, we define varargs directly here.
 */

#ifdef __GNUC__
#define va_start(v, l)		__builtin_va_start(v, l)
#define va_end(v)		__builtin_va_end(v)
#define va_arg(v, l)		__builtin_va_arg(v, l)
typedef __builtin_va_list	va_list;
#else
#include_next <stdarg.h>
#endif

#endif /* STDARG_H */
