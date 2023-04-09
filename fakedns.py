from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, UDP
import socket

# Replace the following DNS records with the appropriate IP addresses
dns_records = {
    "www.ItamarGuetta.com": "10.0.0.200"
}

def handle_dns_request(packet):
    # we first check if the packet has dns layer and if its a request
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        print(f"Received DNS request for {packet[DNS].qd.qname.decode()}")
        dns_query_name = packet[DNS].qd.qname.decode().rstrip('.')
        
    # checking if the domain is in my dns_records
        if dns_query_name in dns_records:
            ip = dns_records[dns_query_name]
            print(f"Resolved {dns_query_name} to {ip}")
            
            dns_response = (
                IP(src=packet[IP].dst, dst=packet[IP].src) /
                UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /
                DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                    an=DNSRR(rrname=packet[DNS].qd.qname, ttl=86400, rdata=ip))
            )
            send(dns_response, verbose=0)
        else:
            print(f"Unable to resolve {dns_query_name}")

def main():
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"Starting DNS server on {local_ip}:53")
    
    sniff(filter="udp port 53", prn=handle_dns_request, store=0)

if __name__ == "__main__":
    main()
