---
layout: post
title:  "Exploit Education: Phoenix (Stack)"
date:   2021-03-02 11:30:56 +0200
categories: exploiteducation
---

```Phoenix``` is a set of challenges oriented towards introducing its participants to basic system exploitation.
To quote from the website:
Phoenix is the spiritual successor to the Protostar challenges. It covers the following topics:

Network programming
Stack overflows
Format string vulnerabilities
Heap overflows

The idea is to introduce the simplest concepts first, from memory corruption, modification, function redirection, and eventually, executing shellcode. These challenges are available for both 32 bit, and 64 bit mode. The 64 bit challenges are new, and were not available on Protostar.

In this section I will present my solutions to the ```Stack``` challenges.

## Level 0 ##

```This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.```
```cpp
/* phoenix/stack-zero, by https://exploit.education
enix/stack-two, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x0d0a090a
 *
 * If you're Russian to get to the bath room, and you are Finnish when you get
 * out, what are you when you are in the bath room?
 *
 * European!
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  char *ptr;

  printf("%s\n", BANNER);

  ptr = getenv("ExploitEducation");
  if (ptr == NULL) {
    errx(1, "please set the ExploitEducation environment variable");
  }

  locals.changeme = 0;
  strcpy(locals.buffer, ptr);

  if (locals.changeme == 0x0d0a090a) {
    puts("Well done, you have successfully set changeme to the correct value");
  } else {
    printf("Almost! changeme is currently 0x%08x, we want 0x0d0a090a\n",
        locals.changeme);
  }

  exit(0);
}
 *
 * The aim is to change the contents of the changeme variable.
 *
 * Scientists have recently discovered a previously unknown species of
 * kangaroos, approximately in the middle of Western Australia. These
 * kangaroos are remarkable, as their insanely powerful hind legs give them
 * the ability to jump higher than a one story house (which is approximately
 * 15 feet, or 4.5 metres), simply because houses can't can't jump.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  printf("%s\n", BANNER);

  locals.changeme = 0;
  gets(locals.buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts(
        "Uh oh, 'changeme' has not yet been changed. Would you like to try "
        "again?");
  }

  exit(0);
}
```

To quote the C++ standard, ``` volatile is a hint to the implementation to avoid aggressive optimization involving the object because the value of the object might be changed by means undetectable by an implementation.```
Basically, if the compiler sees the ```if (locals.changeme != 0)``` and knows that this will always be false, it will attempt to assemble it as if that ```if``` statement never even existed, getting rid of a variable and thus bringing some optimizations on the table.
However, if we don't want it to do that and instead we would rather it didn't do that, we use the ```volatile``` keyword.
Since ```gets``` is being used, we know from the start that this is going to lead to a buffer overflow vulnerability. All we have to do is find the offset from the start of our input to ```changeme```, by either fuzzing it, or reading the disassembly.

Let's start off by reading the disassembly

![stack01](/assets/images/Phoenix/stack01.png)

Alright, so we can definetely see that ```changeme``` is located at ```rbp-0x10```, from ```<+25>```, which is the equivalent of ```locals.changeme = 0;``` and lines ```<+44>``` and ```<+47>```, which represent ```if (locals.changeme != 0)```.
What is more, we can see that our buffer is being read into starting from ```rbp-0x50```, as ```<+32>``` tells us.
Thus, our payload should look like:
```payload = "a" * (0x50 - 0x10) + non_zero_value```


![stack02](/assets/images/Phoenix/stack02.png)

Success!


## Level 1 ##

```This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.```
```cpp
/*
 * phoenix/stack-one, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x496c5962
 *
 * Did you hear about the kid napping at the local school?
 * It's okay, they woke up.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  printf("%s\n", BANNER);

  if (argc < 2) {
    errx(1, "specify an argument, to be copied into the \"buffer\"");
  }

  locals.changeme = 0;
  strcpy(locals.buffer, argv[1]);

  if (locals.changeme == 0x496c5962) {
    puts("Well done, you have successfully set changeme to the correct value");
  } else {
    printf("Getting closer! changeme is currently 0x%08x, we want 0x496c5962\n",
        locals.changeme);
  }

  exit(0);
}
```

Ah, it looks like it's exactly the same layout! The only differences being the fact that it takes its input from the command line and that this time it requires a specific value for ```locals.changenme```.
Alright then, just like last time, but it must be passed as the first command line argument and a new value.

![stack11](/assets/images/Phoenix/stack11.png)

## Level 2 ##

```Stack Two takes a look at environment variables, and how they can be set.```
```cpp
/*
 * phoenix/stack-two, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x0d0a090a
 *
 * If you're Russian to get to the bath room, and you are Finnish when you get
 * out, what are you when you are in the bath room?
 *
 * European!
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  char *ptr;

  printf("%s\n", BANNER);

  ptr = getenv("ExploitEducation");
  if (ptr == NULL) {
    errx(1, "please set the ExploitEducation environment variable");
  }

  locals.changeme = 0;
  strcpy(locals.buffer, ptr);

  if (locals.changeme == 0x0d0a090a) {
    puts("Well done, you have successfully set changeme to the correct value");
  } else {
    printf("Almost! changeme is currently 0x%08x, we want 0x0d0a090a\n",
        locals.changeme);
  }

  exit(0);
}
```

The same layout again, only this time we have to pass the payload through an environment variable!

![stack21](/assets/images/Phoenix/stack21.png)

## Level 3 ##

```
Stack Three looks at overwriting function pointers stored on the stack.

Hints

    You can use gdb and objdump to determine where the complete_level() function is in memory.
```
```cpp
/*
 * phoenix/stack-three, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x0d0a090a
 *
 * When does a joke become a dad joke?
 *   When it becomes apparent.
 *   When it's fully groan up.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void complete_level() {
  printf("Congratulations, you've finished " LEVELNAME " :-) Well done!\n");
  exit(0);
}

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int (*fp)();
  } locals;

  printf("%s\n", BANNER);

  locals.fp = NULL;
  gets(locals.buffer);

  if (locals.fp) {
    printf("calling function pointer @ %p\n", locals.fp);
    fflush(stdout);
    locals.fp();
  } else {
    printf("function pointer remains unmodified :~( better luck next time!\n");
  }

  exit(0);
}
```

Again, the same layout. However, as we are indicated to, we need to look up in the disassembly the virtual address of the ```complete_level``` function.

![stack31](/assets/images/Phoenix/stack31.png)

Alright, now for our payload!

![stack32](/assets/images/Phoenix/stack32.png)

## Level 4 ##

```
Stack Four takes a look at what can happen when you can overwrite the saved instruction pointer (standard buffer overflow).

Hints

    The saved instruction pointer is not necessarily directly after the end of variable allocations – things like compiler padding can increase the size. Did you know that some architectures may not save the return address on the stack in all cases?
    GDB supports “run < my_file” to direct input from my_file into the program.
```
```cpp
/*
 * phoenix/stack-four, by https://exploit.education
 *
 * The aim is to execute the function complete_level by modifying the
 * saved return address, and pointing it to the complete_level() function.
 *
 * Why were the apple and orange all alone? Because the bananna split.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void complete_level() {
  printf("Congratulations, you've finished " LEVELNAME " :-) Well done!\n");
  exit(0);
}

void start_level() {
  char buffer[64];
  void *ret;

  gets(buffer);

  ret = __builtin_return_address(0);
  printf("and will be returning to %p\n", ret);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

Alright, we are definetely going to need to take a look at the disassembly

![stack41](/assets/images/Phoenix/stack41.png)

And let's take a look at how the stack looks before reading our input.

![stack42](/assets/images/Phoenix/stack42.png)

Brilliant! Looks like we can start overwriting our saved instruction pointer starting at offset 88, since that is where the next instruction's address from main is after the ```call``` instruction. Now let's send our payload and finish it!

![stack43](/assets/images/Phoenix/stack43.png)

## Level 5 ##

```
As opposed to executing an existing function in the binary, this time we’ll be introducing the concept of “shell code”, and being able to execute our own code.

Hints

    Don’t feel like you have to write your own shellcode just yet – there’s plenty on the internet.
    If you wish to debug your shellcode, be sure to make use of the breakpoint instruction. On i386 / x86_64, that’s 0xcc, and will cause a SIGTRAP.
    Make sure you remove those breakpoints after you’re done.
```
```cpp
/*
 * phoenix/stack-five, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * What is green and goes to summer camp? A brussel scout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void start_level() {
  char buffer[128];
  gets(buffer);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

Again, as soon as we see ```gets```, we can be 100% sure that there is going to be an overflow.
We are hinted to try and execute ```/bin/sh```, which implies either the use of ```system```, or the use of shellcode.
I am going to use this [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php), as it is the shortest I could find. If you want to see how you can build your own shellcode, I detailed my process while solving the challenges from Narnia.

![stack51](/assets/images/Phoenix/stack51.png)

As we can see, from the start of the buffer we are allowed to write into to the saved return address, there are 136 bytes (128 bytes of the buffer and 8 bytes for the saved base pointer). So, we can insert our shellcode in there somewhere. We can then surround it with nops and try to guess the address of the stack pointer which we could use to overwrite the return address with. However, I prefer to do it as if I had ASLR enabled.
Thus, I found a good ROP gadget just for that, ```jmp rax```. 

![stack52](/assets/images/Phoenix/stack52.png)

This is useful because, as it can be seen from the above screenshot, ```<+8>``` makes ```rax``` hold the value of ```rsp```, where we could insert our shellcode.
So, our payload can look like:
```payload = shellcode + "a" * (136 - sizeof(shellcode)) + ROPgadget```

![stack53](/assets/images/Phoenix/stack53.png)


## Level 6 ##

```
Where does Stack Six go wrong, and what can you do with it?

Depending on the architecture you’re doing this on, you may need to explore more and be creative with how to solve this level.

The macro GREET is architecture dependent.
```
```cpp
/*
 * phoenix/stack-six, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * Why do fungi have to pay double bus fares? Because they take up too
 * mushroom.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *what = GREET;

char *greet(char *who) {
  char buffer[128];
  int maxSize;

  maxSize = strlen(who);
  if (maxSize > (sizeof(buffer) - /* ensure null termination */ 1)) {
    maxSize = sizeof(buffer) - 1;
  }

  strcpy(buffer, what);
  strncpy(buffer + strlen(buffer), who, maxSize);

  return strdup(buffer);
}

int main(int argc, char **argv) {
  char *ptr;
  printf("%s\n", BANNER);

#ifdef NEWARCH
  if (argv[1]) {
    what = argv[1];
  }
#endif

  ptr = getenv("ExploitEducation");
  if (NULL == ptr) {
    // This style of comparison prevents issues where you may accidentally
    // type if(ptr = NULL) {}..

    errx(1, "Please specify an environment variable called ExploitEducation");
  }

  printf("%s\n", greet(ptr));
  return 0;
}
```

It would seem that the binary makes use of, yet again, the environment variable ```ExploitEducation``` and passes its address to the ```greet``` function.
Let's also take a look at the disassembly of ```greet``` to see the offsets.

![stack61](/assets/images/Phoenix/stack61.png)

Hmm, alright, so, from what we can see, the buffer stored at our environment variable has its size compared ti ```0x7f``` which is 127, so even if we were to put more bytes into it, it would be capped at 127.
However, the program doesn't seem to take into account the size of ```what``` variable. Let's execute and see how many bytes that has from the output. I am also going to give our environment variable its maximum size in bytes and see what happens.

![stack62](/assets/images/Phoenix/stack62.png)

Looks like we triggered a segmentation fault! And our ```what``` variable seems to have 34 bytes, which allows us to overflow ```buffer```.
From analysing the disassembly, it looks like we would only be able to overwrite the least significant byte of the saved base pointer.
Let's look at main's disassembly as well.

![stack63](/assets/images/Phoenix/stack63.png)

Hmm, okay, nothing interesting, other than the fact that it passes to ```puts``` a heap copy of ```buffer``` through ```rax``` into ```rdi```.
Let's investigate with ```GDB```.
These are the contents of the stack that are of interested to us, before ```strncpy``` is called.

![stack64](/assets/images/Phoenix/stack64.png)

And these are the contents of the stack that are of interested to us, after ```strncpy``` is called.

![stack65](/assets/images/Phoenix/stack65.png)

As we can see the saved return address is stored at ```0x7fffffffffe600``` so there is now way we can touch it.
However, the key here is the ability to overwrite with one byte the saved base pointer! Why? Because of the ```leave``` instruction in our ```main``` function. When ```main```'s base pointer gets restored, it will have our overwritten value. And since ```leave``` puts the base register's value back into the stack pointer, we get to control the return address of the ```main``` function.
Perhaps that is why ```greet``` doesn't use ```leave``` and de-allocates everything manually, it might have been intended as a hint from the author ;).

Now we need to see how our exploit would work outside of ```GDB``` and also find a reasonable stack value to overwrite our base pointer with, to trigger our shellcode located in the environment variable. In order to do that, we need to eliminate the differences between ```GDB``` environment, and ours.
Our environment:

![stack66](/assets/images/Phoenix/stack66.png)

```GDB```'s environment:

![stack67](/assets/images/Phoenix/stack67.png)

From what we can see, we need to ```unset``` the ```LINES```, ```COLUMNS``` environment variables from ```GDB```. What is more, we need to change ```_``` to ```/opt/phoenix/amd64/stack-six```.

![stack68](/assets/images/Phoenix/stack68.png)

Looks about right! (ignore the python errors, it is a problem with my tty)

Now let's get going with ```GDB``` and find our address!

![stack69](/assets/images/Phoenix/stack69.png)

Unfortunately, the environment's variable address is too far away for our range allowed by our one byte overwrite...
BUT! We still have a pointer on ```main```'s stack frame that stores that address and that could be closer!

![stack610](/assets/images/Phoenix/stack610.png)

Indeed! ```ptr``` is stored at ```rbp-0x8``` and holds our desired environment variable's address! This can be seen in the above image, outlining the contents of ```main```'s stack before ```greet``` is called!

Now all we need to do is overwrite our saved base pointer with ```ptr```'s address, minus 8!

![stack611](/assets/images/Phoenix/stack611.png)

## Conclusion ##
This was a great introductive series to basic stack exploitation. I've enjoyed it a lot! It's been a while since I've solved a partial overwrite challenge. Great series! ```Phoenix Format``` challenges are coming next!
