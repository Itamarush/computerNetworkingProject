from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import time

dhcp_ip = "10.0.0.50"
dns_ip = "10.0.0.60"
dhcp_ipList = ["10.0.0.100", "10.0.0.101", "10.0.0.102", "10.0.0.103", "10.0.0.104", "10.0.0.105"
               "10.0.0.106", "10.0.0.107", "10.0.0.108", "10.0.0.109", "10.0.0.110", "10.0.0.111"]
mac_address = RandMAC()

def dhcp_offer(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print("A DISCOVER REQUEST PACKET HAS RECIEVED")
        if len(dhcp_ipList) == 0:
            print("The list is empty")
        else:
            print("The list is not empty, Looking for an IP to send to the client")
        ipToSend = dhcp_ipList[0]
        print(f"{ipToSend} is the chosen IP, sending...")
        offerPacket = Ether(dst="ff:ff:ff:ff:ff:ff") / \
            IP(src=dhcp_ip, dst="255.255.255.255") / \
            UDP(sport=67, dport=68) / \
            BOOTP(op=2, yiaddr=ipToSend, siaddr=dhcp_ip, giaddr="0.0.0.0", xid=packet[BOOTP].xid) / \
            DHCP(options=[("message-type", "offer"),
                           ("subnet_mask", "255.255.255.0"),
                           ("router", "10.0.0.50"),
                           ("name_server", "10.0.0.60"),
                           ("lease_time", 86400), "end"])
        time.sleep(1)
        sendp(offerPacket, iface="enp0s3")
        print(f"DHCP offer sent to the client, waiting for response")
        # sniff(filter="udp and dst port 67", prn=dhcp_ack, count=1, iface="enp0s3")

    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print("Got a Request")
        print(f"{packet[BOOTP].yiaddr} assigned to client and added to IP list")
        ackPacket = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src=dhcp_ip, dst="255.255.255.255") / \
                       UDP(sport=67, dport=68) / \
                       BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr=packet[BOOTP].siaddr, giaddr="0.0.0.0", xid=packet[BOOTP].xid) / \
                       DHCP(options=[("message-type", "ack"),
                                      ("subnet_mask", "255.255.255.0"),
                                      ("router", "10.0.0.18"),
                                      ("lease_time", 86400), "end"])
        time.sleep(1)
        sendp(ackPacket, iface="enp0s3")
        print(f"DHCP ACK sent to {packet[BOOTP].yiaddr}")

if __name__ == '__main__':
    print("DHCP server is running...")
    sniff(filter="udp and dst port 67", prn=dhcp_offer, iface="enp0s3")
