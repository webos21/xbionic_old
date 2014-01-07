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

// get a thread-local storage (TLS) area
// ref {
//     http://man7.org/linux/man-pages/man2/get_thread_area.2.html
//     http://www.nynaeve.net/?p=180
// }
void *__get_tls(void) {
  void *tls;
  PTEB_7 x = XbNtCurrentTeb();
  tls = x->ThreadLocalStoragePointer;
  return tls;
}
