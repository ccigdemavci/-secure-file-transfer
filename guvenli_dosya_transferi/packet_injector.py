from scapy.all import IP, UDP, send

def inject_fake_packet(src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=8080, payload=b"Malicious packet!"):
    print(f"➡️ Sahte paket gönderiliyor: {src_ip} -> {dst_ip}:{dst_port}")
    try:
        ip = IP(src=src_ip, dst=dst_ip, ttl=64)
        udp = UDP(sport=12345, dport=dst_port)
        packet = ip/udp/payload
        send(packet)
        print("✅ Sahte paket başarıyla gönderildi.")
    except Exception as e:
        print(f"❌ Paket gönderimi sırasında hata oluştu: {e}")

if __name__ == "__main__":
    inject_fake_packet()
