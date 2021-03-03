---
layout: post
title:  "Exploit Education: Phoenix (Format)"
date:   2021-03-03 11:31:56 +0200
categories: exploiteducation
---

Moving on to the next series of levels, the format section of Phoenix introduces participants to the basics of format string vulnerabilities and how to use it to change the control flow of programs.

With that being said, let's get started.

## Level 0 ##
```This level introduces format strings, and how attacker supplied format strings can modify program execution.```
```cpp
/*
 * phoenix/format-zero, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * 0 bottles of beer on the wall, 0 bottles of beer! You take one down, and
 * pass it around, 4294967295 bottles of beer on the wall!
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
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts("Uh oh, 'changeme' has not yet been changed. Would you like to try "
    "again?");
  }

  exit(0);
}
```

The vulnerability stands at the call of the ```sprintf``` function, due to the fact that we can simply read into buffer a format string. The function string will try to interpret that string and will try to look for the next parameter on the stack/register that the format string is supposed to replace.
Let's take a look at the disassembly.

![format01](/assets/images/Phoenix/format01.png)

From what we can see, the buffer we are reading into, has its beginning at an offset of 32 bytes from the beginning of ```changeme```. Let's see what happens if we supply as input a format string that wishes to take from the stack 48 digits.

![format02](/assets/images/Phoenix/format02.png)

Beautiful! It looks like we succeeded and our guess was right! But let's see what actually happens in memory!
This is how the current stack frame looks before ```sprintf``` is called with our input.

![format03](/assets/images/Phoenix/format03.png)

And this is how the current stack frame looks after the call.

![format04](/assets/images/Phoenix/format04.png)

Here, ```rbp``` has the value ```0x7fffffffffffe6b0```, so our ```local.changeme``` is located at ```0x7fffffffffffe6a0``` and we can see it changed. Interestingly, we can also see that the base pointer had its least significant byte also overwritten!
So what happened? Well our changed bytes are ascii character conversion from the hexadecimal bytes that were in the memory that ```sprintf``` extracted through our format string. For example, ```0x20``` is actually the whitespace character used for padding to obtain 16 digits. Also, the resulted numbers on the stack look very much like stack addresses.
For example, the sequence on the second column, third row is equal to ```0xffffe670``` which really looks like a stack address, but it's missing some ```ff```'s because our input takes into account only 4 byte values, we need to increase the size and the output will be much clearer. We want it to be of type ```long long```.
By giving the input ```%llx.%llx.%llx```, the stack frame content after the function call is much clearer!

![format05](/assets/images/Phoenix/format05.png)

It would seem that our stack now contains the string ```7fffffffe670.7ffff7ffc536.1010101010101010". Who could that be? We can get our answer by looking at the registers.

![format06](/assets/images/Phoenix/format06.png)

Looks like those are the exact contents of ```rdx```, ```rcx``` and ```r8``` respectively. This is due to Linux's calling convention, where the arguments are passed in order into the registers ```rdi rsi rdx rcx r8 r9``` and the rest are passed through the stack. Since our format string tells ```sprintf``` to look for three more ```long long``` arguments and insert into the string, it will take them from the registers and thus overwriting our buffer located on the stack with those vaulues, which have 16 digits each, so 48 bytes, exactly what we needed!

## Level 1 ##

```Even more format string fun!```
```cpp
/*
 * phoenix/format-one, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * Why did the Tomato blush? It saw the salad dressing!
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
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0x45764f6c) {
    printf("Uh oh, 'changeme' is not the magic value, it is 0x%08x\n",
    locals.changeme);
  } else {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  }

  exit(0);
}
```

Alright, the same layout, the same offsets, it's just that now we need to overwrite with a specific value, which, finnily, translates to ```lOvE```.
Our payload will be made out of 32 bytes + ```lOvE```, which we can get through some padding.

![format11](/assets/images/Phoenix/format11.png)

## Level 2 ##

```This level introduces being able to write to specific areas of memory to modify program execution.```
```cpp
/*
 * phoenix/format-two, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * What kind of flower should never be put in a vase?
 * A cauliflower.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
      "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[256];

  printf("%s\n", BANNER);

  if (argc > 1) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], sizeof(buf));
    bounce(buf);
  }

  if (changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    puts("Better luck next time!\n");
  }

  exit(0);
}
```

Let's see where ```changeme``` is located.

![format21](/assets/images/Phoenix/format21.png)

Alright, so now all we need to do is find where this value is located on the stack frame of the ```main``` function. That address will be pushed in order to be passed as an argument for ```boounce```.

These are some of the contents of the stack before the call to ```printf``` and, as it can be seen, our desired address is placed on the stack if we give it as input for printf.

![format22](/assets/images/Phoenix/format22.png)

Our address seems to be located at the place where the 12th argument to printf would be, except of course the format string itself.
Let's test our theory and see if my guess was right.

![format23](/assets/images/Phoenix/format23.png)

Looks like I was right.

## Level 3 ##

```This level introduces writing specific values to memory, and how that can be accomplished.```
```cpp
/*
 * phoenix/format-three, by https://exploit.education
 *
 * Can you change the "changeme" variable to a precise value?
 *
 * How do you fix a cracked pumpkin? With a pumpkin patch.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[4096];
  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);

  if (changeme == 0x64457845) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    printf(
        "Better luck next time - got 0x%08x, wanted 0x64457845!\n", changeme);
  }

  exit(0);
}
```
This is the same layout but now our input is taken from ```stdin``` and now we have to force ```changeme``` to a specific value, which can be easily accomplished by using padding format strings.
However, the problem is the output would be too large! The solution is to switch to the address of the next bytes!

After a lot of trial and error, I managed to get the desired value of the least significant byte! Now all we need is to add some whitespaes for the other 3 addresses on the stack!

![format31](/assets/images/Phoenix/format31.png)

And this is my final solution!

![format32](/assets/images/Phoenix/format32.png)

## Level 4 ##

```This level introduces writing to memory in such a way that you can control code execution.```
```cpp
/*
 * phoenix/format-four, by https://exploit.education
 *
 * Can you affect code execution? Once you've got congratulations() to
 * execute, can you then execute your own shell code?
 *
 * Did you get a hair cut?
 * No, I got all of them cut.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

void bounce(char *str) {
  printf(str);
  exit(0);
}

void congratulations() {
  printf("Well done, you're redirected code execution!\n");
  exit(0);
}

int main(int argc, char **argv) {
  char buf[4096];

  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);
}
```
This is the same layout and, as the below screenshot shows, our address is stored on the previous stack frame at the same offset.

![format41](/assets/images/Phoenix/format41.png)

In order to call ```congratulations```, we could try overwriting the saved return address, but ```exit``` is stopping us from doing so.
Since ```exit``` is relocated at runtime through lazy binding, we could simply overwrite its value at its address in the ```GOT``` with ```congratulations```'s address.

![format42](/assets/images/Phoenix/format42.png)

So, we just need to put at the start of the format string the ```GOT``` address just like the previous challenge

![format43](/assets/images/Phoenix/format43.png)

Obviously, this would call an infinite loop, since ```congratulations``` would call itself infinitely.

![format44](/assets/images/Phoenix/format44.png)

Now, for our shellcode, in a similar manner to the previous section, we need to see the stack address of the start of the shellcode inside ```GDB``` and, thus, we need to remove the differences between the two environments.
In ```GDB``` we will write:
```
unset env LINES
unset env COLUMNS
set env _ opt/phoenix/i486/format-four
```
```NOTE: IT IS VERY IMPORTANT THAT YOU ONLY USE ABSOLUTE PATHS WHEN WRITING ENVIRONMENT VARIABLES, otherwise things can get buggy...```

And this is the address we see before the call to ```printf```:

![format45](/assets/images/Phoenix/format45.png)

This is how the stack would look like if I were to give as input a few ```i``` characters (I like them over the classic ```a```'s ;) ).
So our shellcode will stand at address ```0xffffc750```.
We are going to overwrite the same address of ```exit```'s entry in ```GOT```, byte by byte.

![format 46](/assets/images/Phoenix/format46.png)

SUCCESS!!

## Conclusion ##
The last challenge was really great! I actually learned a thing or two, like how creative this byte by byte overwriting format string is. Otherwise, format strings usually involve a lot of arithmetic calculations, but it was definetely fun!
I will soon be going over the ```Heap``` section of challenges from the ```Phoenix``` series.
