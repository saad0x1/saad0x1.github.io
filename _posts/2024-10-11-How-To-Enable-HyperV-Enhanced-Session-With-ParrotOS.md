---
title: How To Enable HyperV Enhanced Session With ParrotOS
author: Saad
date: 2024-10-11 00:00:00 +0500
image: ./Hyper-V.png
categories:
- Tips & Tricks
tags:
  - hyperv
  - parrot
  - tricks
  - xrdp
media_subpath: /assets/img/2024-10-11-How-To-Enable-HyperV-Enhanced-Session-With-ParrotOS
---
Using Parrot OS is fun on Hyper-V which is really fast compare to other hypervisors, but we can't have an Enhanced Session in HyperV with Parrot OS
Which leads to us not being able to copy paste something or hear any audio, but there is one way we can do it, let's take a look.

## Prerequisites

_We need to enable Guest Services for the VM in Hyper-V which can be found in VM Settings as shown below:_
### Via GUI
![](hyperv_vm.png)
### Via PowerShell
```powershell
Set-VM "Your VM Name" -EnhancedSessionTransportType HVSocket
```
## Installing dependencies

We need to install some dependencies that are might not be pre-installed on Parrot OS VM that we have in Hyper-V.

```bash
sudo apt-get -y install hyperv-daemons pulseaudio-module-xrdp xrdp
```

This is going to install `hyperv-daemons` which is a utility to improve user interaction on Linux VMs in Hyper-V.
And then `pulseaudio-module-xrdp`  which provides audio redirection support for XRDP.
`xrdp` is important since it enhanced session is over rdp.
_Enable rdp_.
```
sudo systemctl enable xrdp
```
### Using Kali Tweaks script

```bash
#!/bin/bash
# vim: et sts=4 sw=4

# Configure XRDP, cf. xrdp.ini(5).
# * use vsock transport
# * use rdp security
# * remove encryption validation
# * disable bitmap compression, since its local its much faster
#
# Note: there are several 'port=' statements in the config file,
# we match 'port=3389' (the default value) to make sure to change
# only this line.
cp -f --preserve=all "/etc/xrdp/xrdp.ini" "/etc/xrdp/xrdp.ini.backup"
sed -i \
    -e 's|^ *port=3389|port=vsock://-1:3389|' \
    -e 's|^ *security_layer=.*|security_layer=rdp|' \
    -e 's|^ *crypt_level=.*|crypt_level=none|' \
    -e 's|^ *bitmap_compression=.*|bitmap_compression=false|' \
    /etc/xrdp/xrdp.ini

# Configure the XRDP session manager, cf. sesman.ini(5).
# * set the first X display number available for xrdp-sesman to 0
# * rename the redirected drives to 'shared-drives'.
cp -f --preserve=all "/etc/xrdp/sesman.ini" "/etc/xrdp/sesman.ini.backup"
sed -i \
    -e 's|^ *X11DisplayOffset=.*|X11DisplayOffset=0|' \
    -e 's|^ *FuseMountName=.*|FuseMountName=shared-drives|' \
    /etc/xrdp/sesman.ini

# Ensure the Hyper-V sockets module gets loaded.
echo "hv_sock" > /etc/modules-load.d/hv_sock.conf
systemctl restart systemd-modules-load.service
```
#### chmod it
Save this script with a name you want and make it executable.
```bash
chmod +x runme.sh
bash runme.sh
```

Now restart your Hyper-V VM and you should have the Enhanced Session. In case kali-tweaks script doesn't work you can [try this one](https://gist.github.com/ikr4-m/67023682f949c2c22b0e51d0acb68b05).

## IT WORKS!!

After doing all the steps above, you should get the prompt to change your resolution.
![](hyperv_works.png)

Thanks for reading!!
