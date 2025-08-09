import socket
import sys
from struct import pack

def send_dns_query(server_ip, server_port, domain):
   
    transaction_id = b"\x12\x34"  
    flags = b"\x01\x00"  
    qdcount = b"\x00\x01"  
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    
    qname = b"".join(pack("B", len(part)) + part.encode() for part in domain.split(".")) + b"\x00"
    qtype = b"\x00\x01" 
    qclass = b"\x00\x01" 

    packet = transaction_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(packet, (server_ip, server_port))
    data, _ = s.recvfrom(512)
    s.close()
    return data

def parse_dns_response(data):
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    pos = 12

    
    for _ in range(qdcount):
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 5  

    ips = []
    
    for _ in range(ancount):
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1

        rtype = int.from_bytes(data[pos:pos+2], "big")
        rclass = int.from_bytes(data[pos+2:pos+4], "big")
        ttl = int.from_bytes(data[pos+4:pos+8], "big")
        rdlength = int.from_bytes(data[pos+8:pos+10], "big")
        rdata = data[pos+10:pos+10+rdlength]

        if rtype == 1 and rdlength == 4:  
            ip = ".".join(str(b) for b in rdata)
            ips.append(ip)

        pos += 10 + rdlength

    return ips

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <DNS server IP> <domain>")
        sys.exit(1)

    dns_server = sys.argv[1]
    domain = sys.argv[2]

    response = send_dns_query(dns_server, 53, domain)
    ips = parse_dns_response(response)

    print(f"Response IPs for {domain} from {dns_server}:")
    for ip in ips:
        print(f" - {ip}")
