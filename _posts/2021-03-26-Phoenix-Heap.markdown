---
layout: post
title:  "Exploit Education: Phoenix (Heap)"
date:   2021-03-26 18:38:56 +0200
categories: exploiteducation
---

This stage of the ```Phoenix``` series introduces the concept of ```Heap Exploitation``` and teaches the basics of Heap data manipulation.

## Level 0 ##
```This level provides an introduction to heap data manipulation, and how that can affect program execution.```

```cpp
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control, and execute the winner function?
 *
 * Why do C programmers make good Buddhists?
 * Because they're not object orientated.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct data {
  char name[64];
};

struct fp {
  void (*fp)();
  char __pad[64 - sizeof(unsigned long)];
};

void winner() {
  printf("Congratulations, you have passed this level\n");
}

void nowinner() {
  printf(
      "level has not been passed - function pointer has not been "
      "overwritten\n");
}

int main(int argc, char **argv) {
  struct data *d;
  struct fp *f;

  printf("%s\n", BANNER);

  if (argc < 2) {
    printf("Please specify an argument to copy :-)\n");
    exit(1);
  }

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  strcpy(d->name, argv[1]);

  printf("data is at %p, fp is at %p, will be calling %p\n", d, f, f->fp);
  fflush(stdout);

  f->fp();

  return 0;
}
```

Since ```strcpy``` is used with our commandline argument and no length check is done, we can clearly do some sort of overflow on the heap.

Luckily, the binary tells us exactly the offset between the two buffers:

![heap01.png](/assets/images/Phoenix/heap01.png)

Let's test this out!

![heap02.png](/assets/images/Phoenix/heap02.png)

Looks like the first level is fairly easy! Let's get the winning function's address and get our flag!

![heap03.png](/assets/images/Phoenix/heap03.png)


## Level 1 ##

```This level explores what can be done with data overwrites.```

```cpp
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control?
 *
 * Which vegetable did Noah leave off the Ark?
 * Leeks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct heapStructure {
  int priority;
  char *name;
};

int main(int argc, char **argv) {
  struct heapStructure *i1, *i2;

  i1 = malloc(sizeof(struct heapStructure));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct heapStructure));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}

void winner() {
  printf(
      "Congratulations, you've completed this level @ %ld seconds past the "
      "Epoch\n",
      time(NULL));
}
```

Once again, it looks like the length of the commandline arguments is not checked, allowing us to do an overflow.

In order to take control we can simply pass through the first argument a string long enough to overcome the offset between ```i1->name``` and ```i2->name``` and then overwrite the value of ```i2->name``` to the address of ```GOT```'s entry for a function we would like to call.
Thus, when the next strcpy is called, our second argument will be written into ```GOT```.

First, let's see the offsets between buffers inside the heap:

```i1-name```'s location in ```GDB```:

![heap11.png](/assets/images/Phoenix/heap11.png)

```i2->name```'s location in ```GDB```:

![heap12.png](/assets/images/Phoenix/heap12.png)

So, our offset between where the buffers are written to is ```0x20```, now we need to calculate the offset between the addresses of these buffers that are passed to ```strcpy```.

The first malloc chunk's user memory is located at ```0xf7e69028``` as we can see in the ```eax``` register after the first ```malloc```. This is the address of the first buffer:

![heap13.png](/assets/images/Phoenix/heap13.png)

The second malloc chunk's user memory will be at ```0xf7e69038```, this being 

![heap14.png](/assets/images/Phoenix/heap14.png)

These being the addresses where our struct heap pointers are allocated.

By analysing the heap contents at the beginning of the first buffer we can see where the address of the second buffer is located, at exactly ```0x14``` bytes from our buffer:

![heap15.png](/assets/images/Phoenix/heap15.png)

Now all we need is the location of where ```puts``` will be relocated and we can overwrite this with the address of ```winner```.

The final payload:

![heap16.png](/assets/images/Phoenix/heap16.png)


## Level 2 ##

```This level explores why you should always explictly initialize your allocated memory, and what can occur when pointer values go stale.```

```cpp
/*
 * phoenix/heap-two, by https://exploit.education
 *
 * This level examines what can happen when heap pointers are stale. This level
 * is completed when you see the "you have logged in already!" message.
 *
 * My dog would, without fail, always chase people on a bike. As soon as he saw
 * someone, he would immediately take off. I spoke to the vet to see if they
 * could be of any help, but they weren't. I spoke to several different dog
 * behaviouralists to see if they have any ideas on how to stop getting him
 * chasing people on a bike. The dog behaviouralists were unable to help. I
 * searched high and low to work out ways to find a way to stop him from
 * chasing people on a bike, to no avail. Eventually, I had no choice but to
 * take the bike away from him.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv) {
  char line[128];

  printf("%s\n", BANNER);

  while (1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if (fgets(line, sizeof(line), stdin) == NULL) break;

    if (strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(struct auth));
      memset(auth, 0, sizeof(struct auth));
      if (strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if (strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if (strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if (strncmp(line, "login", 5) == 0) {
      if (auth && auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

We are met with a binary that takes commands in an infinite loop, allocating memory as necessary.

Clearly, there is a ```Use after Free``` vulnerability, since we can use the ```auth``` command, followed by ```reset``` and then followed by ```login```, which enables us to reuse a chunk.
The moment we allocate memory for ```auth```, a chunk that contains at least 36 bytes is returned to the user, ```auth->auth``` taking the last 4 bytes. The moment we free it, with ```reset```, the ```glibc Heap``` saves this chunk in a bin in order to properly recycle it.

Thus, the next time we allocate another chunk, if we make it of the same size, we would have returned to the suer the exact same chunk that ```auth``` points to. This will allow us to manipulate the ```login``` condition.

A good way to do this is to first use ```auth``` to allocate the memory, followed by a ```reset``` to deallocate it, then a ```service``` with a 32 byte buffer, for ````auth->name```, plus a few non-zero bytes to overwrite ```auth->auth```

![heap21.png](/assets/images/Phoenix/heap21.png)

I have outlined above where our ```auth->auth``` would be located.

As you can see, we bypassed the ```login``` check!

## Level 3 ##

```This level explores why you should always explictly initialize your allocated memory, and what can occur when pointer values go stale.```

```cpp
/*
 * phoenix/heap-three, by https://exploit.education
 *
 * This level is linked against ftp://gee.cs.oswego.edu/pub/misc/malloc-2.7.2.c
 * version 2.7.2, with a SHA1 sum of 407329d164e4989b59b9a828760acb720dc5c7db
 * more commonly known as "dlmalloc", Doug Lea Malloc
 *
 * Can you hijack flow control, and execute winner()? Afterwards, how
 * about your own code? This level is solvable on Linux i386 easily enough,
 * as for other architectures, it may not be possible, or may require some
 * creativity - let me know what you come up with :)
 *
 * My friend told me that nothing rhymes with orange.
 * I told them, "No, it doesn't".
 *
 * Or, more seriously, https://www.youtube.com/watch?v=lPcR5RVXHMg
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void winner() {
  printf("Level was successfully completed at @ %ld seconds past the Epoch\n",
      time(NULL));
}

int main(int argc, char **argv) {
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

Once again, there is no check on the commandline arguments we can provide, thus allowing us to really mess around with the buffers.
In order to fully udnerstand the ways we can exploit this type of vulnerability, you need to udnerstand how ```ptmalloc```, Linux's default memory allocator works.

The best resource for this is [this](https://github.com/shellphish/how2heap) Github page. It contains many other references, as well as PoC's. It is also what I used to fully grasp how the Heap works in Linux.

That being said, let's look for ways of exploiting this binary!
First, let's do a normal run, and see how the heap looks! I am going to pass 32 ```a```'a to ```argv[1]```, 32 ```b```'s to ```argv[2]``` and 32 ```c```'s to ```argv[3]```. You can easily get the memory mappings of the process in ```GDB``` through the ```info proc mappings``` command.

After first ```malloc```:

![heap31.png](/assets/images/Phoenix/heap31.png)

After second ```malloc```:

![heap32.png](/assets/images/Phoenix/heap32.png)

After last ```malloc```:

![heap33.png](/assets/images/Phoenix/heap33.png)

After ```strcpy``` calls:

![heap34.png](/assets/images/Phoenix/heap34.png)

After first ```free```:

![heap35.png](/assets/images/Phoenix/heap35.png)

After second ```free```:

![heap36.png](/assets/images/Phoenix/heap36.png)

After last ```free```:

![heap37.png](/assets/images/Phoenix/heap37.png)

Notice how the pointers to the previously freed malloc chunk is placed at where user data was located previously!

Another interesting thing is the ```0x29``` which contains relevant metadata, such as the ```PREV_INUSE``` bit. ```0x29``` is equal to ```41``` in binary: 32 bytes of user data + 2 * 4 bytes (prev_size and chunk size) + 1 to set the ```PREV_INUSE``` bit. So, the actual chunk size if 40 bytes!

So, all of the chunks are placed in fast bins (no ```tcache``` in this ```glibc``` version) since the ```PREV_INUSE``` is not unset and they are not consolidated. It's also because they contain single directional pointers, just like a singly linked-list. A good way to start exploiting this is by changing the size attribute through the ```strcpy``` calls, so that some chunks may not end up in fastbins and would end up in unsorted bins instead!

The key here is to force a chunk to be put into an unsorted bin, by modifying its size through an overflow. Because unsorted bins are kept in a doubly linked-list, during consolidation the forward and backward pointers need to be updated, thus two dereferences happen:

```cpp
#define 
unlink(P, BK, FD) {
  FD = P->fd;                                                          
  BK = P->bk;                                                          
  FD->bk = BK;  // *(*P + 8) + 12) = *(P + 12)                                                       
  BK->fd = FD;  // *(*(P + 12) + 8) = *(P + 8)                                                       
}
```
Thus, if we were to place into ```FD + 12``` the ```GOT``` entry for ```puts``` and into ```BK``` the address of ```winner```, we will be able to execute ```winner```... right? Well, not really! The second line also does a dereference, which would then dereference the ```.text``` section, which is not writable, thus resulting in a ```Segmentation Fault```.
The workaround here is to place a piece of shellcode that would force execution to ```winner```.
Something among the lines of ```push address_of_winner; ret``` should work. We could place that into the heap during the ```strcpy``` calls. This would avoid the ```Segmentation Fault``` since the Heap is writable.
So, we could simply place the address of that shellcode where ```bk``` would be and the ```GOT - 12``` entry where ```fd``` should be.

Now we need to take care of the backwards cosolidation phase, more specifically this piece of code is of concern:

```cpp
if (!prev_inuse(p)) {
    prevsize = p->prev_size;
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    unlink(p, bck, fwd);
}
```

So, in order to pass this check and get to that much desired ```unlink``` we could make it so that ```prevsize``` is 0 to make it unlink itself. However, that would cause trouble for our payload, since we cannot accept null characters. So let's make it unlink itself at another offset and adjust our addresses from there.
Let's say I want it to unlink itself at offset ```8```, then I would need to overwrite ```prevsize``` with ```0xfffffff8``` for a ```-8```.

The same will also happen with forward consolidation! We can't keep the same size, because our payload would contain null bytes when trying to overwrite, thus we will need a negative value. If we would force the memory deallocator to look 40 bytes behind at chunk B, then it would look at chunk C which would have the ```PREV_INUSE``` bit unset and would consolidate the chunks wrong resulting in a ```Segmentation Fault```. We will need to make it look at chunk A, because the next chunk after A is chunk B, which will be marked as ```PREV_INUSE```. This way the forward consolidation would stop abruptly.
Thus, we need to overwrite Chunk C's current size with ```-80``` or ```0xffffffb0```.

Using the same technique we have used in previous challenged, we can find out the addresses we need through ```GDB``` by unsetting certain environment variables. We now need ```winner```'s address (```0x080487d5```) to pass to the shellcode (I will pass the shellcode into chunk A).

All the paddings will be done with ```nop```s.

![heap38.png](/assets/images/Phoenix/heap38.png)

Thus, we finished the Heap section of the Phoenix series! Level 3 was definetely very hard, as it required a lot of reading and unedrstanding of ```ptmalloc```.
The next challenge of Phoenix will introduce us to basic network communications through sockets.
