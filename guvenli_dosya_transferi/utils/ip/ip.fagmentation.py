from scapy.all import IP, UDP, Raw, send

def ip_checksum(header_bytes):
    if len(header_bytes) % 2:
        header_bytes += b'\x00'

    checksum = 0
    for i in range(0, len(header_bytes), 2):
        word = (header_bytes[i] << 8) + header_bytes[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff


data = b"A" * 3000
MTU = 1400
IP_HEADER_LEN = 20
FRAG_SIZE = MTU - IP_HEADER_LEN

dst_ip = "192.168.1.10"
src_ip = "192.168.1.5"

udp_header = UDP(sport=12345, dport=80)
udp_header_len = len(bytes(udp_header))

payload_offset = 0
fragments = []

# İlk fragment UDP başlığı ile birlikte
first_chunk_size = FRAG_SIZE - udp_header_len
first_payload = udp_header / Raw(load=data[:first_chunk_size])
fragments.append(
    IP(dst=dst_ip, src=src_ip, id=1234, flags="MF", frag=0, proto=17, ttl=64) / first_payload
)
payload_offset += first_chunk_size

# Diğer fragmentler
while payload_offset < len(data):
    chunk = data[payload_offset:payload_offset + FRAG_SIZE]
    frag_offset = int(payload_offset / 8)
    more_fragments = "MF" if (payload_offset + FRAG_SIZE) < len(data) else 0
    fragments.append(
        IP(dst=dst_ip, src=src_ip, id=1234, flags=more_fragments, frag=frag_offset, proto=17, ttl=64) / Raw(load=chunk)
    )
    payload_offset += FRAG_SIZE

# Checksum manuel hesapla ve güncelle
for i, pkt in enumerate(fragments):
    print(f"\n--- Fragment {i+1} ---")

    # IP header bytes al (checksum sıfırlanmış olmalı)
    ip_raw = bytes(pkt)[:IP_HEADER_LEN]
    ip_raw = ip_raw[:10] + b'\x00\x00' + ip_raw[12:]  # Checksum alanını sıfırla (byte 10 ve 11)

    # Checksum'u hesapla
    checksum = ip_checksum(ip_raw)

    # Checksum'u pakete ekle
    pkt.chksum = checksum

    # Paket ve checksum'u göster
    pkt.show2()
