
all: simple

simple:
	nasm -g -f elf64 -o simple.o simple.asm
	ld simple.o -o simple

fib:
	gcc -g fib.c -o fib

.PHONY: simple fib
