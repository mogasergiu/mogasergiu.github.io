---
layout: post
title:  "OverTheWire: Leviathan"
date:   2021-02-15 14:57:56 +0200
categories: overthewire
---

### Level 0 -> 1 ###
The password can be found inside the ```HTML``` file inside the ```.backup``` directory:
```
leviathan0@leviathan:~$ ls -al
total 24
drwxr-xr-x  3 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
drwxr-x---  2 leviathan1 leviathan0 4096 Aug 26  2019 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
leviathan0@leviathan:~$ ls .backup
bookmarks.html
leviathan0@leviathan:~$ cat .backup/bookmarks.html | grep "pass"
```

### Level 1 -> 2 ###
We are presented with a binary with its ```SUID``` flag set:
```
leviathan1@leviathan:~$ ls -l
total 8
-r-sr-x--- 1 leviathan2 leviathan1 7452 Aug 26  2019 check
```
It seems to ask us for a password:
```
leviathan1@leviathan:~$ ./check 
password: idk
Wrong password, Good Bye ...
```

Disassembling the binary we can see that some strings are placed on the stack:
```
leviathan1@leviathan:~$ objdump -rd check -M intel | less
```
```
 804854a:       83 ec 20                sub    esp,0x20
 804854d:       c7 45 f0 73 65 78 00    mov    DWORD PTR [ebp-0x10],0x786573 ; sex
 8048554:       c7 45 e9 73 65 63 72    mov    DWORD PTR [ebp-0x17],0x72636573 ; secr
 804855b:       66 c7 45 ed 65 74       mov    WORD PTR [ebp-0x13],0x7465 ; et
 8048561:       c6 45 ef 00             mov    BYTE PTR [ebp-0x11],0x0
 8048565:       c7 45 e5 67 6f 64 00    mov    DWORD PTR [ebp-0x1b],0x646f67 ; god
 804856c:       c7 45 e0 6c 6f 76 65    mov    DWORD PTR [ebp-0x20],0x65766f6c ; love
 8048573:       c6 45 e4 00             mov    BYTE PTR [ebp-0x1c],0x0
```

And we can see that our input is compared to the first string:
```
 80485aa:       8d 45 f4                lea    eax,[ebp-0xc]
 80485ad:       50                      push   eax
 80485ae:       e8 fd fd ff ff          call   80483b0 <strcmp@pl
 ```
 So, our answer is ```sex```.
 ```
 leviathan1@leviathan:~$ ./check 
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2        
```

### Level 2 -> 3 ###
Again, we are presented with a binary that seems to be able to print files and has its ```SUID``` set for user ```leviathan3```, however it can't be that easy... can it?
```
leviathan2@leviathan:~$ ls -la
total 28
drwxr-xr-x  2 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-r-sr-x---  1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
-rw-r--r--  1 root       root        675 May 15  2017 .profile
leviathan2@leviathan:~$ ./printfile 
*** File Printer ***
Usage: ./printfile filename
leviathan2@leviathan:~$ ./printfile /etc/leviathan_pass/leviathan3
You cant have that file...
```
Let's investigate the ```ltrace```:
```
leviathan2@leviathan:~$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 2, 0xffffd684, 0x8048610 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)      = -1
puts("You cant have that file..."You cant have that file...
)               = 27
+++ exited (status 1) +++
```
What if we give it some file we are allowed to read?
```
leviathan2@leviathan:~$ touch /tmp/hello
leviathan2@leviathan:~$ ltrace ./printfile /tmp/hello
__libc_start_main(0x804852b, 2, 0xffffd694, 0x8048610 <unfinished ...>
access("/tmp/hello", 4)                          = 0
snprintf("/bin/cat /tmp/hello", 511, "/bin/cat %s", "/tmp/hello") = 19
geteuid()                                        = 12002
geteuid()                                        = 12002
setreuid(12002, 12002)                           = 0
system("/bin/cat /tmp/hello" <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 0
+++ exited (status 0) +++
```
It looks like it uses ```cat``` to output the file contents. What if we create a symbolic link to that file and try again?
```
leviathan2@leviathan:~$ ln -sf /etc/leviathan_pass/leviathan3 /tmp/hello
leviathan2@leviathan:~$ ltrace ./printfile /tmp/hello
__libc_start_main(0x804852b, 2, 0xffffd694, 0x8048610 <unfinished ...>
access("/tmp/hello", 4)                          = -1
puts("You cant have that file..."You cant have that file...
)               = 27
+++ exited (status 1) +++
```
Nope, still doesn't work. So, the ```access``` syscall is our gatekeeper here. What if we give it a filename with spaces in it?
```
leviathan2@leviathan:~$ touch /tmp/hello\ hi
leviathan2@leviathan:~$ ltrace ./printfile /tmp/hello\ hi
__libc_start_main(0x804852b, 2, 0xffffd694, 0x8048610 <unfinished ...>
access("/tmp/hello hi", 4)                       = 0
snprintf("/bin/cat /tmp/hello hi", 511, "/bin/cat %s", "/tmp/hello hi") = 22
geteuid()                                        = 12002
geteuid()                                        = 12002
setreuid(12002, 12002)                           = 0
system("/bin/cat /tmp/hello hi"/bin/cat: /tmp/hello: No such file or directory
/bin/cat: hi: No such file or directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 256
+++ exited (status 0) +++
```
Well, would you look at that! We just bypassed ```access``` and ```system``` just tries to ```cat``` ```hi``` as if it's a different file! Let's solve that missing file problem and get our flag:
```
leviathan2@leviathan:$ cd /etc/leviathan_pass/
leviathan2@leviathan:/etc/leviathan_pass$ touch /tmp/hi
leviathan2@leviathan:/tmp$ touch /tmp/hi\ leviathan3
leviathan2@leviathan:/etc/leviathan_pass$ ~/printfile /tmp/hi\ leviathan3
```

### Level 3 -> 4
Another challenge, another binary! Let's check it out!
```
leviathan3@leviathan:~$ ls -la
total 32
drwxr-xr-x  2 root       root        4096 Aug 26  2019 .
drwxr-xr-x 10 root       root        4096 Aug 26  2019 ..
-rw-r--r--  1 root       root         220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root        3526 May 15  2017 .bashrc
-r-sr-x---  1 leviathan4 leviathan3 10288 Aug 26  2019 level3
-rw-r--r--  1 root       root         675 May 15  2017 .profile
leviathan3@leviathan:~$ ./level3 
Enter the password> idk
bzzzzzzzzap. WRONG
leviathan3@leviathan:~$ ltrace ./level3 
__libc_start_main(0x8048618, 1, 0xffffd6a4, 0x80486d0 <unfinished ...>
strcmp("h0no33", "kakaka")                       = -1
printf("Enter the password> ")                   = 20
fgets(Enter the password> idk
"idk\n", 256, 0xf7fc55a0)                  = 0xffffd4b0
strcmp("idk\n", "snlprintf\n")                   = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                       = 19
+++ exited (status 0) +++
``` 
This seems to be simple! It just compares our input to ```snlprintf```! Let's get the flag!
```
leviathan3@leviathan:~$ ./level3 
Enter the password> snlprintf
[You've got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
```

### Level 4 -> 5 ###
This was a very trivial challenge.
```
total 24
drwxr-xr-x  3 root root       4096 Aug 26  2019 .
drwxr-xr-x 10 root root       4096 Aug 26  2019 ..
-rw-r--r--  1 root root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root root        675 May 15  2017 .profile
dr-xr-x---  2 root leviathan4 4096 Aug 26  2019 .trash
leviathan4@leviathan:~$ ls .trash/
bin
leviathan4@leviathan:~$ .trash/bin 
```
This prints some characters' binary encoding. Just throw them in a binary to ASCII converter and you get your flag :).

### Level 5 -> 6 ###
This challenge is also easier than the previous ones. We are given a binary that seems to want to print the contents of a file ```/tmp/file.log``` after which it gets deleted:
```
eviathan5@leviathan:~$ ls -la
total 28
drwxr-xr-x  2 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-r-sr-x---  1 leviathan6 leviathan5 7560 Aug 26  2019 leviathan5
-rw-r--r--  1 root       root        675 May 15  2017 .profile
leviathan5@leviathan:~$ ./leviathan5 
Cannot find /tmp/file.log
leviathan5@leviathan:~$ touch /tmp/file.log
leviathan5@leviathan:~$ ./leviathan5 
leviathan5@leviathan:~$ cat /tmp/file.log
cat: /tmp/file.log: No such file or directory
leviathan5@leviathan:~$ ls /tmp/file.log
ls: cannot access '/tmp/file.log': No such file or directory
```
So the simple solution is just creating a symbolic link to leviathan6's password:
```
leviathan5@leviathan:~$ ln -sf /etc/leviathan_pass/leviathan6 /tmp/file.log
leviathan5@leviathan:~$ ./leviathan5 
```
And this is how we get our flag.

### Level 6 -> 7
This time we have a binary that converts 4 character strings to integers:
```
leviathan6@leviathan:~$ ls
leviathan6
leviathan6@leviathan:~$ ./leviathan6 
usage: ./leviathan6 <4 digit code>
leviathan6@leviathan:~$ ./leviathan6 6969
Wrong
leviathan6@leviathan:~$ ltrace ./leviathan6 6969
__libc_start_main(0x804853b, 2, 0xffffd6a4, 0x80485e0 <unfinished ...>
atoi(0xffffd7ed, 0, 0xf7e40890, 0x804862b)       = 6969
puts("Wrong"Wrong
)                                    = 6
+++ exited (status 0) +++
```
Unfortunately, it seems that we can't get anything valuable out of the ```ltrace```.
The answer stands in the disassembly!
Our input is compared to a value on the stack
```
804858f:       3b 45 f4                cmp    eax,DWORD PTR [ebp-0xc]
```
And we have that value written on the stack right here!
```
 804854f:       c7 45 f4 d3 1b 00 00    mov    DWORD PTR [ebp-0xc],0x1bd3
```
Easy enough, 0x1bd3 is 7123 in decimal. Let's get our flag!
```
leviathan6@leviathan:~$ ./leviathan6 7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
```

### Level 7 ###
Welp, looks like we are done! :)
```
leviathan7@leviathan:~$ ls
CONGRATULATIONS
```