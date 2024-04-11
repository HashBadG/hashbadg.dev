---
title: '[Cyberdefenders] - Ramnit'
date: '11/04/2024'
lastmod: '11/04/2024'
tags: ['Volatility', 'Memory']
summary: 'Here is my writeup for Ramnit challenge that I completed on Cyberdefenders.'
draft: false
author: ['H4shBadG']
---

# Summary

Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings. This analysis is critical in understanding the breach and preventing further compromise.

## Q1 - We need to identify the process responsible for this suspicious behavior. What is the name of the suspicious process?

Analyzing the memory dump led me to the `ChromeSetup.exe` process (PID 4628) for 2 main reasons. 
1. First looking through the different processes, nothing came to my mind so I proceed to do a netstat. The ouptut of this looked like this.

```
Volatility 3 Framework 2.6.1

Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0xca82b7deeb20  TCPv4   192.168.19.133  49763   2.18.162.9      443     ESTABLISHED     2500    svchost.exe     2024-02-01 19:52:57.000000 
0xca82b7abdaf0  TCPv4   192.168.19.133  49739   40.115.3.253    443     ESTABLISHED     3356    svchost.exe     2024-02-01 19:51:25.000000 
0xca82b87e8a20  TCPv4   192.168.19.133  49697   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b8bd7a20  TCPv4   192.168.19.133  49695   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b7861a20  TCPv4   192.168.19.133  49761   2.16.149.135    80      ESTABLISHED     2500    svchost.exe     2024-02-01 19:52:57.000000 
0xca82b87f3010  TCPv4   192.168.19.133  49691   192.229.221.95  80      CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b8005a20  TCPv4   192.168.19.133  49693   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b3fc74d0  TCPv4   192.168.19.133  49759   2.18.162.9      443     ESTABLISHED     2500    svchost.exe     2024-02-01 19:52:56.000000 
0xca82b8ba9a20  TCPv4   192.168.19.133  49699   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b8b98a20  TCPv4   192.168.19.133  49760   2.18.162.9      443     ESTABLISHED     2500    svchost.exe     2024-02-01 19:52:57.000000 
0xca82b7f1fa20  TCPv4   192.168.19.133  49692   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b8564050  TCPv4   192.168.19.133  49755   20.199.120.85   443     ESTABLISHED     3356    svchost.exe     2024-02-01 19:52:25.000000 
0xca82b38b0730  TCPv4   192.168.19.133  49765   52.179.219.14   443     ESTABLISHED     2500    svchost.exe     2024-02-01 19:52:58.000000 
0xca82b78cba20  TCPv4   192.168.19.133  49694   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b7e5a700  TCPv4   192.168.19.133  49700   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
0xca82b8bc2b30  TCPv4   192.168.19.133  49682   58.64.204.181   5202    SYN_SENT        4628    ChromeSetup.ex  2024-02-01 19:48:51.000000
0xca82b8baea20  TCPv4   192.168.19.133  49696   95.100.200.202  443     CLOSE_WAIT      5912    WWAHost.exe     2024-02-01 19:49:20.000000 
```

Looking at the communications, I saw that the `ChromeSetup.exe` was communicating with an IP from Hong Kong. I found this pretty weird and choose to dump the files from the process with the and analyze it on [VT](https://virustotal.com). Uploading the images of the `ChromeSetup.exe` file, I found quite surprising results :)

![TBH kinda sus :)](/images/Ramnit/Ramnit.png)

Response: `ChromeSetup.exe`

## Q2 - To eradicate the malware, what is the exact file path of the process executable?

Looking through the previous analysis, I can retrieve the location of the file launching the process from the `PSTree` output.

```
4628	4568	ChromeSetup.exe
0xca82b830a300	4	-	1	True	2024-02-01 19:48:50.000000 	N/A	
\Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe	
"C:\Users\alex\Downloads\ChromeSetup.exe" 	C:\Users\alex\Downloads\ChromeSetup.exe
```

## Q3 - Identifying network connections is crucial for understanding the malware's communication strategy. What is the IP address it attempted to connect to?

From Q1, the response is `58.64.204[.]181`

## Q4 - To pinpoint the geographical origin of the attack, which city is associated with the IP address the malware communicated with?

Searching for this IP on [ipinfo.io](https://ipinfo.io) gave me the following result :

![IPinfo](/images/Ramnit/Ramnit2.png)

Response: Hong Kong

## Q5 - Hashes provide a unique identifier for files, aiding in detecting similar threats across machines. What is the SHA1 hash of the malware's executable?

Calculating the SHA1 for the executable file give the following result:

```
$ sudo sha1sum 4628-ChromeSetup/file.0xca82b85325a0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat
b9921cc2bfe3b43e457cdbc7d82b849c66f119cb  4628-ChromeSetup/file.0xca82b85325a0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat
```

## Q6 - Understanding the malware's development timeline can offer insights into its deployment. What is the compilation UTC timestamp of the malware?

Response in the details page of the [VT scan](https://www.virustotal.com/gui/file/56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652/details) which is `2019-12-01 08:36:04`


## Q7 - Identifying domains involved with this malware helps in blocking future malicious communications and identifying current possible communications with that domain in our network. Can you provide the domain related to the malware?

Now on the [relations](https://www.virustotal.com/gui/file/56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652/relations) page we can see the domain contacted by the malware and it's this one : `dnsnb8.net`