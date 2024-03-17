section .data
    hw db "Hello, World!",10
    hw2 db "Hello, World!2",10
    tv_delay dq 0, 500000000
    increment dq 0

section .bss
    test_bss resb 256

section .text
    global _start


%macro print 2
%%_print:
    mov rax, 1 ; id for sys_write
    mov rdi, 1 ; filedescriptor (0 stdin, 1 stdout, 2 stderr)
    mov rsi, %1 ; the data buffer (kinda like char*)
    mov rdx, %2 ; the length of the databuffer
    syscall

%endmacro

%macro sleep 0
%%_sleep:
    mov rax, 35 ; nanosleep id
    mov rdi, tv_delay
    mov rsi, 0 ; the second argument is usually 0 according to the documentation
    syscall

%endmacro

print2:
    print hw2, 15
    ret

_start:

    print hw, 14
loopy:
    mov rax, [increment]
    inc rax
    mov [increment], rax
    sleep
    print hw, 14
    mov rax, [increment]
    cmp rax, 4
    jne loopcont
    call print2
loopcont:
    mov rax, [increment]
    cmp rax, 5
    jl loopy

    mov rax, 60 ; id for sys_exit
    mov rdi, 0 ; error code (0 is for successuful)
    syscall
