from scapy.all import IP, TCP, Raw, wrpcap
import random

packets = []

# Generate 10.000 paket dominan NORMAL (10% SYN, 90% normal)
for i in range(10000):
    src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = "192.168.10.2"
    src_port = random.randint(1024, 65535)

    roll = random.random()

    if roll < 0.10:
        # Paket SYN (wajar, awal koneksi HTTP biasa)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="S", window=65535, seq=random.randint(1000,99999))
    elif roll < 0.40:
        # Paket ACK
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="A", window=65535, seq=random.randint(1000,99999))
    elif roll < 0.75:
        # Paket PSH+ACK (HTTP request/response)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="PA", window=65535, seq=random.randint(1000,99999)) / \
              Raw(load=b"GET / HTTP/1.1\r\nHost: 192.168.10.2\r\n\r\n")
    elif roll < 0.90:
        # Paket FIN+ACK (tutup koneksi normal)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="FA", window=65535, seq=random.randint(1000,99999))
    else:
        # Paket RST (reset koneksi)
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=80, flags="R", window=65535, seq=random.randint(1000,99999))

    packets.append(pkt)

wrpcap('test_normal.pcap', packets)
print(f"File test_normal.pcap berhasil dibuat: {len(packets)} paket")
print(f"Estimasi SYN  : ~1000 paket (10%)")
print(f"Estimasi Normal : ~9000 paket (90%)")