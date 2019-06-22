gcc -std=c99 -Wall -Wextra -nostdlib -ffreestanding -mconsole -Os -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -o freestanding.exe freestanding.c -lkernel32
