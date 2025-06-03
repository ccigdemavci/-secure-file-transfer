from scapy.all import IP, UDP, send, hexdump

# 1. IP başlığı oluştur
ip_packet = IP(
    dst="192.168.1.10",    # hedef IP adresi
    src="192.168.1.5",     # kaynak IP adresi
    ttl=64,                # TTL değeri (Time To Live)
    flags="MF",            # More Fragments flag
    id=1001                # ID alanı (fragmentation için önemli)
)

# 2. UDP başlığı ve payload
udp_packet = UDP(sport=12345, dport=80) / "Test mesajı".encode("utf-8")

# 3. Paket oluştur
packet = ip_packet / udp_packet

# 4. Paket içeriğini analiz et
print("Paketin IP Başlığı Özeti:")
packet.show()

# 5. Hexdump (detaylı görünüm)
print("\nPaketin Hexdump'ı:")
hexdump(packet)

# 6. Paket gönderme (isteğe bağlı)
# send(packet)
