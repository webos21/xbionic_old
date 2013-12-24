@echo off
setlocal

REM You have to change the PATH & SPEC_DIR

set PATH=C:\DevSoft\xiDev\toolchains\mingw64\bin;%PATH%

"gcc" %* -specs "D:/WorkData/GitLocal/xbionic/ant/mingw32/emul/lib/cmjo-bionic-gcc-win.specs"
