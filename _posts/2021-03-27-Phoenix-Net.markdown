---
layout: post
title:  "Exploit Education: Phoenix (Net)"
date:   2021-03-27 20:14:56 +0200
categories: exploiteducation
---

## Level 0 ##

```Can you convert string provided to the native endian of the architecture the binary is running on?```

Also, we are told that our service is running on port ```64010```

```cpp
/*
 * phoenix/net-zero, by https://exploit.education
 *
 * What did the fish say when he swam head first into a wall?
 * Dam!
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  uint32_t i, j;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  printf("Please send '%u' as a little endian, 32bit integer.\n", i);

  if (read(0, (void *)&j, sizeof(j)) != sizeof(j)) {
    errx(1, "unable to read %d bytes from stdin", sizeof(j));
  }

  if (i == j) {
    printf("You have successfully passed this level, well done!\n");
  } else {
    printf("Close - you sent %u instead\n", j);
  }

  return 0;
```

Alright, let's see what we have here!

![net01](/assets/images/Phoenix/net01.png)

Ok, let's convert it into hexadecimal and send it away!

![net02](/assets/images/Phoenix/net02.png)

I was too lazy to write a python script so I started coding straight from the console :).

## Level 1 ##

We are asked to do the exact same thing but in ```ASCII``` instead of ```little endian```. Also the service runs on port ```64011```.

```cpp
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  uint32_t i;
  char buf[12], fub[12], *q;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  if (write(1, &i, sizeof(i)) != sizeof(i)) {
    errx(1, "unable to write %d bytes", sizeof(i));
  }

  if (fgets(buf, sizeof(buf), stdin) == NULL) {
    errx(1, "who knew that reading from stdin could be so difficult");
  }
  buf[sizeof(buf) - 1] = 0;

  q = strchr(buf, '\r');
  if (q) *q = 0;
  q = strchr(buf, '\n');
  if (q) *q = 0;

  sprintf(fub, "%u", i);
  if (strcmp(fub, buf) == 0) {
    printf("Congratulations, you've passed this level!\n");
  } else {
    printf("Close, you sent \"%s\", and we wanted \"%s\"\n", buf, fub);
  }

  return 0;
}
```

The steps are exactly the same, just the format differs!

![net11](/assets/images/Phoenix/net11.png)

Only this time we are given raw bytes, which we could simply convert to integer and then to string.

![net12](/assets/images/Phoenix/net12.png)

## Level 2 ##

```And now for some additional fun.```

The service runs on port ```64012```

```cpp
/*
 * phoenix/net-two, by https://exploit.education
 *
 * Shout out to anyone who doesn't know what the opposite of in is.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  int i;
  unsigned long quad[sizeof(long)], result, wanted;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\nFor this level, sizeof(long) == %d, keep that in mind :)\n",
      BANNER, (int)sizeof(long));

  if (getrandom((void *)&quad, sizeof(quad), 0) != sizeof(quad)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(quad));
  }

  result = 0;
  for (i = 0; i < sizeof(long); i++) {
    result += quad[i];
    if (write(1, (void *)&quad[i], sizeof(long)) != sizeof(long)) {
      errx(1, "Why have you foresaken me, write()");
    }
  }

  if (read(0, (void *)&wanted, sizeof(long)) != sizeof(long)) {
    errx(1, "Unable to read\n");
  }

  if (result == wanted) {
    printf("You have successfully passed this level, well done!\n");
  } else {
    printf("Whoops, better luck next time. Receieved %lu, wanted %lu\n", wanted,
        result);
  }

  return 0;
}
```

Let's see what this is all about!

![net21](/assets/images/Phoenix/net21.png)

It looks like the program just generates 16 random bytes, adds them up 4 by 6 and compares our input to that sum.
The steps to solve this are exactly the same, the only difference being that we will read the bytes in a ```for loop``` to obtain the sum.

![net22](/assets/images/Phoenix/net22.png)

Looks like we have a problem! The sum goes waaay past the ```long``` maximum number. We will need to make sure we pass only the first 32 bits!

![net23](/assets/images/Phoenix/net23.png)

Using this mask, we make sure we only send in the least significat 32 bits!

And this concludes the ```Net``` challenges offered by ```Phoenix```. Overall, it was a good introduction in how to send payloads remotely using python, but it seemed to be too easy and not involve any exploitation at all, really. 

