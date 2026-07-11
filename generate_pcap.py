from scapy.all import IP, TCP, Raw, wrpcap
import random

packets = []

# Generate 10.000 paket campuran dengan dominan SYN (70% SYN, 30% normal)
for i in range(10000):
    src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = "192.168.10.2"
    src_port = random.randint(1024, 65535)
    
    roll = random.random()
    
    if roll < 0.70:
        # Paket SYN (serangan)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="S", window=512, seq=random.randint(1000,99999))
    elif roll < 0.80:
        # Paket ACK (normal)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="A", window=65535, seq=random.randint(1000,99999))
    elif roll < 0.90:
        # Paket PSH+ACK (normal HTTP)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="PA", window=65535, seq=random.randint(1000,99999)) / \
              Raw(load=b"GET / HTTP/1.1\r\nHost: 192.168.10.2\r\n\r\n")
    else:
        # Paket FIN (normal close)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="FA", window=65535, seq=random.randint(1000,99999))
    
    packets.append(pkt)

wrpcap('test_mixed.pcap', packets)
print(f"File test_mixed.pcap berhasil dibuat: {len(packets)} paket")
print(f"Estimasi SYN: ~7000 paket (70%)")
print(f"Estimasi Normal: ~3000 paket (30%)")