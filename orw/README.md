Testing:

nasm -f elf main.asm && ld -m elf_i386 -o main main.o && objdump -d main && ./main

Create shellcode:

nasm -f bin main.asm
