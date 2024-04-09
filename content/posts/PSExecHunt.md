---
title: '[Cyberdefenders] - PSExec Hunt'
date: '09/04/2024'
lastmod: '09/04/2024'
tags: ['Network Analysis', 'PCAP', 'Wireshark', 'Exfiltration']
summary: 'Here is my writeup for PSExec Hunt challenge that I completed on Cyberdefenders.'
draft: false
author: ['H4shBadG']
---

# Summary

Our Intrusion Detection System (IDS) has raised an alert, indicating suspicious lateral movement activity involving the use of PsExec. To effectively respond to this incident, your role as a SOC Analyst is to analyze the captured network traffic stored in a PCAP file.

## Q1 - In order to effectively trace the attacker's activities within our network, can you determine the IP address of the machine where the attacker initially gained access?

At first glance, the attack seems to be originated from 10.0.0.133. On the packets below we can clearly see some attacks using SMB exploitation. 

![SMB Attack on 10.0.0.130](/images/PSExecHunt/PSExecHunt.png)

Response: 10.0.0.130

## Q2 - To fully comprehend the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?

As we can see in packet 132 and looking in the NTLMv2 Response, we have the machine's hostname :

```
......NTLMSSP.........8........|...wk.........`.`.H...
.aJ....S.A.L.E.S.-.P.C.....S.A.L.E.S.-.P.C.....S.A.L.E.S.-.P.C.....S.a.l.e.s.-.P.C.....S.a.l.e.s.-.P.C........p........
```

Response: `SALES-PC`

## Q3 - After identifying the initial entry point, it's crucial to understand how far the attacker has moved laterally within our network. Knowing the username of the account the attacker used for authentication will give us insights into the extent of the breach. What is the username utilized by the attacker for authentication?

Parsing the different packets following the attack, we can observe a NTLMSSP. I found the following account used in the Session ID : 

```
Session Id: 0x0000300000000039 Acct:ssales Domain: Host:HR-PC
```

Response: `ssales`

## Q4 - After figuring out how the attacker moved within our network, we need to know what they did on the target machine. What's the name of the service executable the attacker set up on the target?

The following packets (especially the 144) mentionned `PSEXESVC.exe` file which is the service for PSExec.

Response: PSEXESVC.exe

## Q5 - We need to know how the attacker installed the service on the compromised machine to understand the attacker's lateral movement tactics. This can help identify other affected systems. Which network share was used by PsExec to install the service on the target machine?

As seen in this packet in the tree id below :

```

        Tree Id: 0x00000005  \\10.0.0.133\ADMIN$
            [Tree: \\10.0.0.133\ADMIN$]
            [Share Type: Physical disk (0x01)]
            [Connected in Frame: 139]
        Session Id: 0x0000300000000039 Acct:ssales Domain: Host:HR-PC
            [Account: ssales]
            [Domain: ]
            [Host: HR-PC]
            [Authenticated in Frame: 133]
        Signature: 00000000000000000000000000000000
        [Response in: 318]
    Write Request (0x09)
        StructureSize: 0x0031
        Data Offset: 0x0070
        Write Length: 65536
        File Offset: 131072
        GUID handle File: PSEXESVC.exe
            File Id: 0000001e-000c-0000-0500-00000c000000
            [Frame handle opened: 145]
            [Frame handle closed: 325]
```

The network share used to install the service is `ADMIN$`.

## Q6 - We must identify the network share used to communicate between the two machines. Which network share did PsExec use for communication?

The net share used for PSExec communication is likely the `IPC$` share as the Admin is only writeable and the attacker seems to redirect STDIN and STDOUT to `IPC$`. Images below :

![PSEXEC Communication over IPC](/images/PSExecHunt/PSExecHunt-2.png)

## Q7 - Now that we have a clearer picture of the attacker's activities on the compromised machine, it's important to identify any further lateral movement. What is the machine's hostname to which the attacker attempted to pivot within our network?

Following the investigation on `10.0.0.130`, we can see that the `PSEXECSVC.exe` file has been sent to `10.0.0.131` which match the hostname `MARKETING-PC`