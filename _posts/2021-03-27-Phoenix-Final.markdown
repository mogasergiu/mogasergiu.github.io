---
layout: post
title:  "Exploit Education: Phoenix (Final)"
date:   2021-03-27 21:38:56 +0200
categories: exploiteducation
---

This is the last series of challenges of the ```Phoenix``` wargame. Let's have some fun! :)

## Level 0 ##

```The beginning of the end of the Phoenix exercises :) Remote stack overflow.```

The service runs on port ```64003```.

```cpp
/*
 * phoenix/final-zero, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable.
 *
 * A woman has twins and gives them up for adoption.
 *
 * One of them goes to a family in Egypt and is named Amal. The other goes to a
 * family in Spain. They name him Juan.
 *
 * Years later, Juan sends a picture of himself to his birth mother. Upon
 * receiving the picture, she tells her husband that she wishes she also had a
 * picture of Amal. He responds, "They're twins! If you've seen Juan, you've
 * seen Amal."
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *s);

/*
 * Read the username in from the network
 */

char *get_username() {
  char buffer[512];
  char *q;
  int i;

  memset(buffer, 0, sizeof(buffer));
  gets(buffer);

  /* Strip off trailing new line characters */
  q = strchr(buffer, '\n');
  if (q) *q = 0;
  q = strchr(buffer, '\r');
  if (q) *q = 0;

  /* Convert to lower case */
  for (i = 0; i < strlen(buffer); i++) {
    buffer[i] = toupper(buffer[i]);
  }

  /* Duplicate the string and return it */
  return strdup(buffer);
}

int main(int argc, char **argv, char **envp) {
  char *username;

  printf("%s\n", BANNER);
  fflush(stdout);

  username = get_username();
  printf("No such user %s\n", username);
}
```

From the very start, the ```gets``` function screams at us: ```BUFFER OVERFLOW!!!!!```.

So, from what we can see, the maximum length of our buffer is ```512``` (which ```gets``` renders useless :) ) and a null byte is placed at the first ```\r``` or ```\n``` character. Afterwards, our input is turned into uppercase version of our bytes... which is bad news.

Luckily, we could use our previous discovery by stop this from happening by placing a ```\r``` somewhere before our payload so that only the bytes up to our payload are uppercase'd.

Thus, we could simply overwrite the return address of ```get_username```'s stack frame! We could do so by passing an approximate stack address around our shellcode. Obviously, we should precede our shellcode with some ```nop```'s to make sure execution flow lands where we want it to.

I will use this [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php). Now, all we need is some stack address!

First, let's find the offset from the beginning of our buffer to our return address!

![final01](/assets/images/Phoenix/final01.png)

So the offset is ```0x220 + 8 (saved base pointer)``` bytes.

Now, for our stack address...

![final02](/assets/images/Phoenix/final02.png)

This is right before ```ret``` is executed, and it looks like ```0x7fffffffe4b8``` might be a good candidate for our return address. Alright let's get to our payload!

![final03](/assets/images/Phoenix/final03.png)


## Level 1 ##

```Remote format string!```

The service runs on port ```64014```.

```cpp
/*
 * phoenix/final-one, by https://exploit.education
 *
 * Even more format string fun!
 *
 * The world's leading expert on European wasps walks into a record shop. He
 * asks the assistant “Do you have ‘European Vespidae Acoustics Volume 2? I
 * believe it was released this week.”
 *
 * “Certainly,” replies the assistant. “Would you like to listen before you buy
 * it?”
 *
 * "That would be wonderful," says the expert, and puts on a pair of
 * headphones.
 *
 * He listens for a few moments and says to the assistant, “I'm terribly sorry,
 * but I am the world's leading expert on European wasps and this is not
 * accurate at all. I don't recognize any of those sounds. Are you sure this is
 * the correct recording?”
 *
 * The assistant checks the turntable, and replies that it is indeed European
 * Vespidae Acoustics Volume 2. The assistant apologizes and lifts the needle
 * onto the next track.
 *
 * Again the expert listens for a few moments and then says to the assistant,
 * "No, this just can't be right! I've been an expert in this field for 43
 * years and I still don't recognize any of these sounds."
 *
 * The assistant apologizes again and lifts the needle to the next track.
 *
 * The expert throws off the headphones as soon as it starts playing and is
 * fuming with rage.
 *
 * "This is outrageous false advertising! I am the world's leading expert on
 * European wasps and no European wasp has ever made a sound like the ones on
 * this record!"
 *
 * The manager of the shop overhears the commotion and walks over.
 *
 * "What seems to be the problem, sir?"
 *
 * "This is an outrage! I am the world's leading expert on European wasps.
 * Nobody knows more about them than I do. There is no way in hell that the
 * sounds on that record were made by European wasps!"
 *
 * The manager glances down and notices the problem instantly.
 *
 * "I'm terribly sorry, sir. It appears we've been playing you the bee side."
 */

#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char username[128];
char hostname[64];
FILE *output;

void logit(char *pw) {
  char buf[2048];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n",
      hostname, username, pw);

  fprintf(output, buf);
}

void trim(char *str) {
  char *q;

  q = strchr(str, '\r');
  if (q) *q = 0;
  q = strchr(str, '\n');
  if (q) *q = 0;
}

void parser() {
  char line[128];

  printf("[final1] $ ");

  while (fgets(line, sizeof(line) - 1, stdin)) {
    trim(line);
    if (strncmp(line, "username ", 9) == 0) {
      strcpy(username, line + 9);
    } else if (strncmp(line, "login ", 6) == 0) {
      if (username[0] == 0) {
        printf("invalid protocol\n");
      } else {
        logit(line + 6);
        printf("login failed\n");
      }
    }
    printf("[final1] $ ");
  }
}

int testing;

void getipport() {
  socklen_t l;
  struct sockaddr_in sin;

  if (testing) {
    strcpy(hostname, "testing:12121");
    return;
  }

  l = sizeof(struct sockaddr_in);
  if (getpeername(0, (void *)&sin, &l) == -1) {
    err(1, "you don't exist");
  }

  sprintf(hostname, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
}

int main(int argc, char **argv, char **envp) {
  if (argc >= 2) {
    testing = !strcmp(argv[1], "--test");
    output = stderr;
  } else {
    output = fopen("/dev/null", "w");
    if (!output) {
      err(1, "fopen(/dev/null)");
    }
  }

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("%s\n", BANNER);

  getipport();
  parser();

  return 0;
}
```

Oh, boy! A format string vulnerability! This is going to take a looooooooooooooooong time and a lot of calculations...
Judging by how the ```Format``` levels were, this is going to take some time, so bucke up!

From what we can see, ```logit``` is the vulnerable part of the code that contains a format string vulnerability. More specifically, it is the line for:

```  fprintf(output, buf);```

Looks like we also need to pass a username first. Let's see what this is about.

![final11](/assets/images/Phoenix/final11.png)

Yep! It definetely is a format string vulnerability. We can exploit this the same way we exploited the format string vulnerabilities from the ```Format``` challenges.

We can simply write enough bytes to properly overwrite the ```GOT``` entry of a function, so that when that function is called we can redirect execution flow.

Since ```printf``` is called immediately after ```logit```, we can try to overwrite its ```GOT``` entry!
 
![final12](/assets/images/Phoenix/final12.png)

Now, similarly to the last levels of ```Format``` we could overwrite at this address, in a byte by byte manner! We could overwrite with the address of a place in memory somewhere on the stack close to our [shellcode](http://shell-storm.org/shellcode/files/shellcode-827.php)!

Let's find a potential address:

![final13](/assets/images/Phoenix/final13.png)

We can see that our input starts with an offset of 1 from ```0xffffcebd```, so we will need to provide that.

![final14](/assets/images/Phoenix/final14.png)

So, it looks like we will need to provide 10 ```%x```'s before we would get into our payload. We could place our ```printf```'s ```GOT``` entry addresses beginning from there and increase it byte by byte and carefully overwrite it with the correct stack address of our shellcode.

![final15](/assets/images/Phoenix/final15.png)

And the screenshot above shows how the stack would look with that input. It would seem that our shellcode could start at ```0xffffcedc```.

Let's get to calculating the format string paddings!

```
gef➤  p/d 0xdc - 130
$6 = 90
gef➤  p/d 0x1ce - 0xdc
$7 = 242
gef➤  p/d 0x1ff - 0x1ce
$8 = 49
gef➤  p/d 0x2ff - 0x1ff
$9 = 256
```

I hope this is going to be good enough, let's test it out locally.

![final16](/assets/images/Phoenix/final16.png)

Looks like we are very close (2 bytes off!) let's adjust the shellcode address!

![final17](/assets/images/Phoenix/final17.png)

It may seem that I also miscalculated some offsets as well...

![final18](/assets/images/Phoenix/final69420.png)

Success! We made it work!

This level was not as hard exploitation-wise as it was arithmetic-wise... as always, lots of calculations with trial and error needed for format string vulnerabilities.
