---
title: '[Cyberdefenders] - Boss Of The SOC 1'
date: '03/03/2023'
lastmod: '03/03/2023'
tags: ['Splunk', 'Blue Team', 'Ransomware', 'BOTS']
draft: false
summary: 'Here is my writeup for Boss Of The SOC 1 that I completed on Cyberdefenders.'
author: ['H4shBadG']
---

### Summary

The focus of this hands on lab will be an APT scenario and a ransomware scenario. You assume the persona of Alice Bluebird, the analyst who has recently been hired to protect and defend Wayne Enterprises against various forms of cyberattack.

In this scenario, reports of the below graphic come in from your user community when they visit the Wayne Enterprises website, and some of the reports reference "P01s0n1vy." In case you are unaware, P01s0n1vy is an APT group that has targeted Wayne Enterprises. Your goal, as Alice, is to investigate the defacement, with an eye towards reconstructing the attack via the Lockheed Martin Kill Chain.

### 1. What is the name of the company that makes the software that you are using for this competition ? Just a six-letter word with no punctuation.

Answer :

```
Splunk
```

### 2. What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities ?

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com
| stats count by src_ip
```

**Output :**

|   src_ip  |   count   |
|:---------:|:---------:|
192.168.250.70  |   11493
23.22.63.114    |   2884
40.80.148.42    |   38416

This query return 3 results. 2 Public addresses and 1 private address. We can already eliminate the private one as it seems not to be an insider attack in the syllabus.

Time to search for headers !

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com  
| stats count by src_ip, src_headers
```

We see some weird packets from `40.80.148[.]42` involving Acunetix Scanner. This seems to be what we searched for.

**Packet example :**
|   src_ip  |   src_headers |
|:---------:|:--------------|
40.80.148.42|	CONNECT www.acunetix.wvs:443 HTTP/1.1 Host: imreallynotbatman.com Connection: Keep-alive Accept-Encoding: gzip,deflate User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21 **Acunetix-Product: WVS/10.0 (Acunetix Web Vulnerability Scanner - Free Edition) Acunetix-Scanning-agreement: Third Party Scanning PROHIBITED Acunetix-User-agreement: http://www.acunetix.com/wvs/disc.htm** Accept: \*/*

**Response :**

```
40.80.148.42
```

### 3. What company created the web vulnerability scanner used by Po1s0n1vy ? Type the company name. (For example, "Microsoft" or "Oracle")

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com  
| stats count by src_ip, src_headers
```

Related to Q2. 

**Reponse :**

```
Acunetix
```

### 4. What content management system is imreallynotbatman.com likely using ? (Please do not include punctuation such as . , ! ? in your answer. We are looking for alpha characters only.)

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com src_ip="40.80.148.42" action=allowed
| stats count by uri,action
```

A Content Management System ([CMS](https://en.wikipedia.org/wiki/Content_management_system)) is used on our customer website. To find it, we are going to search for allowed action on the website during the vulnerability scan. Looking through the logs, we can see a lot of allowed action against "Joomla" CMS. After analysing all of these informations, it seems to be confirmed that the customer website use Joomla to manage its components.

**Example :**

```http
GET /joomla/administrator/components/com_extplorer/images/_edit.png HTTP/1.1
Accept: image/png, image/svg+xml, image/*;q=0.8, */*;q=0.5
Referer: http://imreallynotbatman.com/joomla/administrator/index.php?option=com_extplorer&tmpl=component
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
Host: imreallynotbatman.com
If-Modified-Since: Wed, 10 Aug 2016 04:16:55 GMT
If-None-Match: "526cdb7bef2d11:0"
DNT: 1
Connection: Keep-Alive
Cookie: 7598a3465c906161e060ac551a9e0276=9qfk2654t4rmhltilkfhe7ua23
```

**Response :**

```
Joomla
```

### 5. What is the name of the file that defaced the imreallynotbatman.com website ? Please submit only the name of the file with the extension (For example, "notepad.exe" or "favicon.ico").

**Used Filter :**

```sql
index="botsv1" c_ip="192.168.250.70"
| rex field=_raw "/(?<fullname>[^\./]*\.\w{3,4})[\s'\"<>\(\)]"
| stats count by fullname
```

When a site is defaced, it means that the original picture has been download by its server. In the filter above, we search for the filename downloaded by our webserver using a regex named `fullname`. Here is the output.

**Output :**

| fullname        | count    |
| ----------------|----------|
com_joomlaupdate.xml| 1|
list.xml|4
poisonivy-is-coming-for-you-batman.jpeg|3
translationlist_3.xml|1

**Response :**

```
poisonivy-is-coming-for-you-batman.jpeg
```

### 6. This attack used dynamic DNS to resolve to the malicious IP. What is the fully qualified domain name (FQDN) associated with this attack ?

**Used Filter :**

```sql
index="botsv1" c_ip="192.168.250.70" | rex field=_raw "/(?<fullname>[^\./]*\.\w{3,4})[\s'\"<>\(\)]" | search fullname="poisonivy-is-coming-for-you-batman.jpeg"
| table request,site
```

Using what we used in the last question, we can filter with the full filename and get the site on which it was downloaded. In this case, it appears to be `prankglassinebracket.jumpingcrab[.]com` on port 1337

**Response :**

```
prankglassinebracket.jumpingcrab.com
```

### 7. What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises ?

Looking for the domain in [VirusTotal](https://www.virustotal.com/gui/domain/prankglassinebracket.jumpingcrab.com/relations), we get the following IP address in the relations page `23.22.63.114`

**Response :**

```
23.22.63.114
```

### 8. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address most likely associated with the Po1s0n1vy APT group ?

I was not very aware of good CTI platform, so I use Threatcrowd[.]com to find more information.

Beginning by the domain name : http://ci-www.threatcrowd.org/domain.php?domain=prankglassinebracket.jumpingcrab.com

![ThreatCrowd Domain Map](/images/BOTSv1/ThreatCrowd-domainmap.png)

Looking through this map, I recognize the IP address 23.22.63.114 and pivot on this one with Alien Vault OTX. On this page (https://otx.alienvault.com/indicator/hostname/www.po1s0n1vy.com), I found the email address.

![OTX Domain Name](/images/BOTSv1/OTX_domainmap.png)

**Response :**

```
lillian.rose@po1s0n1vy.com
```

### 9. What IP address is likely attempting a brute force password attack against imreallynotbatman.com ?

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method=POST
| stats count by src_ip, form_data, status
```
Back on Splunk, I have been searching for strange POST Method (as we are speaking about brute-force attack) and found that the IP of  was doing some weird request :)

![Brute-Force Attack](/images/BOTSv1/bruteforce.png)

**Response :**

```
23.22.63.114
```

### 10. What is the name of the executable uploaded by Po1s0n1vy ? Please include the file extension. (For example, "notepad.exe" or "favicon.ico")

While I was looking through Joomla stream, I found some logs with filename uploaded by user:
![File Uploaded by User](/images/BOTSv1/fileupload.png)

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" 
| stats count by dest_ip,part_filename{}
```

It may be the `agent.php` but looking through the the `Content-Disposition` field, I saw that the `exe` magic bytes appear in the raw data.

![3791.exe Explanation](/images/BOTSv1/3791_rawdata.png)

**Response :**

```
3791.exe
```

### 11. What is the MD5 hash of the executable uploaded ?

**Used Filter :**

```sql
index="botsv1" 3791.exe md5 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational CommandLine="3791.exe"
| rex field=_raw MD5="(?<md5sum>\w+)"
| table CommandLine, MD5
```

![MD5 Hash](/images/BOTSv1/MD5_hash.png)

Looking on VT, we have something like this. Which seems pretty malicious :
https://www.virustotal.com/gui/file/ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d

**Response :**

```
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

### 12. GCPD reported that common TTP (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear-phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vy's initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

Looking on Virus Total with the APT Group's IP Address,  I found that there is four files communicating with this IP address :
![VT Comm files](/images/BOTSv1/VT_comms.png)

This file is the one we are looking for : https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

**Response:**

```
9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8
```

### 13. What is the special hex code associated with the customized malware discussed in question 12 ? (Hint: It's not in Splunk)

In the community tab on the previous link, we found the hex code :
![Comment](/images/BOTSv1/VT_comments.png)

**Response :**

```
53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21
```

### 14. One of Po1s0n1vy's staged domains has some disjointed "unique" whois information. Concatenate the two codes together and submit them as a single answer.

Using https://www.whoxy.com/, I found the following information.

![Whois information](/images/BOTSv1/whois_info.png)

**Response :**

```
31 73 74 32 66 69 6E 64 67 65 74 73 66 72 65 65 62 65 65 72 66 72 6F 6D 72 79 61 6E 66 69 6E 64 68 69 6D 74 6F 67 65 74
```

### 15. What was the first brute force password used ?

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" form_data=*username*passwd*
| rex field=form_data "username=(?<user>\w+)"
| rex field=form_data "passwd=(?<pw>\w+)"
| table _time, user,pw 
| sort by _time
```

On the Splunk interface, we can see the password attack sorted by time :
![Time Based BF Attack](/images/BOTSv1/time-based-attack.png)

**Response :**

```
12345678
```

### 16. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Hint: we are looking for a six-character word on this one. Which is it ?

! TO-DO !

### 17. What was the correct password for admin access to the content management system running "imreallynotbatman.com" ?

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" form_data=*username*passwd* src_ip="40.80.148.42" 
| rex field=form_data "username=(?<user>\w+)"
| table form_data
 ```

**Response :**

```
batman
```

### 18. What was the average password length used in the password brute-forcing attempt ? (Round to a closest whole integer. For example "5" not "5.23213")

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" form_data=*username*passwd*
| rex field=form_data "passwd=(?<pass>\w+)"
| eval pass_length=len(pass)
| stats avg(pass_length) as avg_pass_length
| eval avg_length_count=round(avg_pass_length, 0)
| table avg_length_count
```

**Response :**

```
6
```

### 19. How many seconds elapsed between the brute force password scan identified the correct password and the compromised login ? Round to 2 decimal places.

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" form_data=*username*passwd*
| rex field=form_data "passwd=(?<pw>\w+)"
| search pw="batman"
| transaction pw
| eval dur=round(duration,2)
| table dur
```

**Response :**

```
92.17
```

### 20. How many unique passwords were attempted in the brute force attempt ?

**Used Filter :**

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http" http_method="POST" form_data=*username*passwd*
| rex field=form_data "passwd=(?<pw>\w+)"
| dedup pw
| stats count
```

**Response :**

```
412
```

### 21. What was the most likely IP address of we8105desk in 24AUG2016 ?

**Used filter :**

```sql
index="botsv1" sourcetype="suricata" cerber then search alert_signature_id in interesting field
```

**Response :**

```
2816763
```

### 22. Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times ? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)

**Used filter :**

```sql
index="botsv1" sourcetype="suricata" cerber then search alert_signature_id in interesting field
```

**Response :**

```
2816763
```

### 23. What fully qualified domain name (FQDN) makes the Cerber ransomware attempt to direct the user to at the end of its encryption phase ?

**Used Filter :**

```sql
index="botsv1" src_ip="192.168.250.100" sourcetype="stream:dns" NOT query=*.local AND NOT query=*.arpa AND NOT query=*.microsoft.com AND NOT *.windows.com AND *.*
| stats count by query
| sort by count asc
```

**Response :**

```
cerberhhyed5frqa.xmfir0.win
```

### 24. What was the first suspicious domain visited by we8105desk in 24AUG2016 ?

**Used Filter :**

```sql
index="botsv1" src_ip="192.168.250.100" sourcetype="stream:dns" NOT query=*.local AND NOT query=*.arpa AND NOT query=*.microsoft.com AND NOT query=*.windows.com AND query=*.*
| table _time, query
| sort by _time desc
```

**Response :**

```
solidaritedeproximite.org
```

### 25. During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of the value of this field ?

**Used Filter :**

```sql
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" .vbs
| rex "<Computer>(?<computer>[a-zA-Z0-9\.-_]+)<\/Computer>"
| rex "\'CommandLine\'>(?<cmdline>[^<]+)<\/Data>"
| eval length=len(cmdline)
| search computer=*we8105desk*
| table _time,cmdline,length
```

**Response :**

```
4490
```

### 26. What is the name of the USB key inserted by Bob Smith ?

```sql
index="botsv1" sourcetype="winregistry" friendlyname
| stats count by registry_value_data
```

**Response :**

```
MIRANDA_PRI
```

### 27. Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server ?

**Used Filter :**
```sql
index="botsv1" src_ip=192.168.250.100 sourcetype="stream:smb"
|stats count by path
```

**Response :**

```
192.168.250.20
```

### 28. How many distinct PDFs did the ransomware encrypt on the remote file server ?

**Used Filter :**

```sql
index=botsv1 sourcetype=wineventlog *.pdf dest="we9041srv.waynecorpinc.local" Source_Address="192.168.250.100"
| stats dc(Relative_Target_Name)
```

**Response :**

```
257
```

### 29. The VBScript found in question 25 launches 121214.tmp. What is the ParentProcessId of this initial launch ?

**Used Filter :**
```sql
index=botsv1 121214.tmp wscript
```

**Response :**

```
3968
```

### 30. The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt ?

```sql
index="botsv1" we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
| stats dc(TargetFilename)
```

**Response :**

```
406
```

### 31. The malware downloads a file that contains the Cerber ransomware crypto code. What is the name of that file ?

**Used Filter :**

```sql
index=botsv1 sourcetype=suricata src_ip="192.168.250.100" solidaritedeproximite.org
```

**Response :**

```
mhtr.jpg
```

### 32. Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use ?

**Used Filter :**

```sql
filter: index=botsv1 sourcetype=suricata src_ip="192.168.250.100" solidaritedeproximite.org
```

**Response :**

```
steganography
```