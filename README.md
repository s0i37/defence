# Hackings style defence tricks
Simple technical techniques that allow you to detect intruders at different stages.
All the techniques presented do not require exclusive rights and can be performed by an ordinary employee - everyone can protect their company.

## Network level \[internal intruder\]
The attacker has just penetrated your corporate network. He doesn't have an account yet and knows almost nothing about your network. His actions will be largely random. It is very important to catch the attacker at this early stage.

### sniffer.py
A running sniffer is not yet a network attack, but its detection is an important prerequisite for possible future attacks. A decent user will not run the sniffer.
A carelessly launched sniffer will make DNS requests that are predictable for us, since the sniffer can show a domain name instead of an IP address. If we periodically send a packet on behalf of an IP address that has a PTR DNS record, and then check the presence of this record in the cache of the corporate DNS server (non-recursive request, aka DNS cache snooping), then we will most likely detect an attacker.

<table border="0">
 <tr>
    <td><img alt="tcpdump" src="img/sniffer-tcpdump.png"></td>
    <td><img alt="sniffer.py" src="img/sniffer.png"></td>
 </tr>
</table>

### tcp.py
The second thing that an internal attacker will most likely use at the very beginning is, of course, port scanning. While he does not have an account and does not understand the structure of the network, he will blindly search for his targets by scanning ports. And sooner or later its packets will reach your computer.
It is quite easy to notice such activity. Of all the traffic, only TCP-SYN packets need to be isolated, which is an excellent marker for this network attack. The `tcp.py` script reacts only to incoming connections; if the number of unique ports is exceeded, an alert occurs.
As a result, even if the attacker scanned only a couple of ports, we will see it.

<table border="0">
 <tr>
    <td><img alt="nmap" src="img/scan-nmap.png"></td>
    <td><img alt="tcp.py" src="img/scan.png"></td>
 </tr>
</table>

### mitm.py

Having listened to enough traffic and scanned his targets, the attacker can finally move on to active action and begin intercepting traffic. It doesn’t matter how he does it, what matters is where it all leads. If an attacker begins to pass others traffic through himself, this will lead to a decrease in IP.ttl in it
This script periodically pings each node in the list. And as soon as the route length (IP.ttl) changes somewhere, it produces a trace instantly calculating the impudent one.
The first thing you need to monitor in this way is, of course, your gateway. However, this detection method allows you to see the consequences of traffic interception outside your own subnet - throughout the entire local network, because it is far from a fact that the attacker will be on the same subnet as you. So the monitoring list can be expanded to include critical servers - your DC, Exchange, SCCM, WSUS, virtualization, etc. Moreover, you can monitor the gateway of each VLAN and even each workstation.

<table border="0">
 <tr>
    <td><img alt="ettercap" src="img/mitm-ettercap.png"></td>
    <td><img alt="mitm.py" src="img/mitm.png"></td>
 </tr>
</table>

Under some circumstances, an attacker may stand not in the middle, but instead of some network device.
Therefore, it is more effective to check traffic interception not through the length of the route, but through the route itself - using tracerouting. This method will also allow you to see particularly cunning attackers who made a TTL fixation before intercepting traffic.
However, the tracing procedure is somewhat longer, and therefore this default detection method is commented out in the script.

### dhcp.py

In local networks, in addition to full-fledged MiTM attacks, “partial” traffic interception attacks can also be carried out. One example would be DHCP allowing you to specify yourself as a gateway or DNS server. By controlling DNS requests, an attacker can selectively redirect connections, thereby implementing partial MiTM.
If IPv6 is not used on the local network, but it is not disabled on network nodes, then an attacker can achieve a similar effect using DHCPv6, since all modern operating systems prefer IPv6 over IPv4.
Both attacks can be detected with single Discover requests. The script periodically sends such broadcast requests to DHCP and DHCPv6. And if someone else besides the legitimate node begins to respond, detection occurs.
Application - only the current network segment.

<table border="0">
 <tr>
    <td><img alt="ettercap" src="img/dhcp-ettercap.png"></td>
    <td><img alt="dhcp.py" src="img/dhcp.png"></td>
 </tr>
</table>

<table border="0">
 <tr>
    <td><img alt="mitm6" src="img/dhcp6-mitm6.png"></td>
    <td><img alt="dhcp.py" src="img/dhcp6.png"></td>
 </tr>
</table>

### netbios.py

In local networks, a much more popular example of partial traffic interception is <ins>responder</ins>. By responding with false responses to name resolution broadcasts (for example through NetBIOS), a hacker can trick your workstation into connecting anywhere, even to himself. As a result, this leads to erroneous connections, with usually automatic end-to-end authentication. In turn, this exposes credentials that can be subject to bruteforce attacks, or can be used to bypass authentication using NTLM relay attacks.
Detecting a responder is easy. You just need to generate a random short name and ask about it broadcast. Script `netbios.py` makes this check. It periodically broadcasts NetBIOS requests with random names to the network. And as soon as the answers begin to arrive - alert.
Application - only the current network segment.

<table border="0">
 <tr>
    <td><img alt="responder" src="img/netbios-responder.png"></td>
    <td><img alt="netbios.py" src="img/netbios.png"></td>
 </tr>
</table>

## Active Directory level \[internal intruder\]

Coming soon

## Wi-Fi level \[external intruder\]

Coming soon
