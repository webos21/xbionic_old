@echo off
setlocal

REM You have to change the PATH & SPEC_DIR

set PATH=C:\DevSoft\x64-4.8.1-release-posix-sjlj-rev5\bin;%PATH%

"gcc" %* -specs "D:/WorkData/GitLocal/xbionic/ant/mingw32/emul/lib/cmjo-bionic-gcc-win.specs"
