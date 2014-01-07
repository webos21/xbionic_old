;
; Copyright 2013 Cheolmin Jo (webos21@gmail.com)
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.
;

.code
Xb__readgsqword PROC
	mov [rsp+8], rcx        ; offset (save parameters as locals)
	sub rsp, 18h
	mov rax, gs:[rcx]		; get gs value with offset in [rcx] ==> x64 TEB
	add rsp, 18h
	ret
Xb__readgsqword ENDP

end
