from scapy.all import IP, UDP, send
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
import subprocess
from scapy.layers.inet import fragment  # Burada fragment fonksiyonunu import ediyoruz.


def manipulate_ip_header(destination_ip):
    """IP başlıklarını manipüle etme fonksiyonu"""
    
    # IP başlığı oluşturuluyor
    ip = IP(dst=destination_ip, ttl=64)  # TTL değeri 64 olarak ayarlanıyor
    tcp = UDP(dport=80, flags="S")  # UDP başlığı, bağlantı başlatma

    # Paket oluşturuluyor
    packet = ip/tcp
    
    # Paket bilgilerini göster
    packet.show()

    # Paketi gönder
    send(packet)
    
    print(f"IP başlıkları manipüle edildi ve paket gönderildi: {destination_ip}")

def fragment_packet(destination_ip):
    """Paketleri parçalama fonksiyonu"""
    
    # Büyük bir veri (2000 byte) oluşturuluyor
    large_data = b"A" * 2000  # 2000 byte'lık veri
    
    # IP ve UDP başlıkları oluşturuluyor
    ip = IP(dst=destination_ip)
    udp = UDP(dport=12345)
    packet = ip/udp/large_data  # IP ve UDP başlıkları ile veriyi birleştiriyoruz
    
    # Paketi parçalara bölüyoruz
    fragments = fragment(packet)
    
    # Parçaları gönderiyoruz
    for frag in fragments:
        send(frag)
        print("Parça gönderildi.")

def measure_latency(destination_ip):
    """Ping ile gecikme ölçümü"""
    
    # Ping komutunu çalıştır
    response = subprocess.run(["ping", "-c", "4", destination_ip], capture_output=True, text=True)
    
    # Sonuçları yazdır
    print(response.stdout)

# IP başlığıyla veri gönderecek fonksiyon
def send_ip_packet(data, server_ip, server_port, ttl=64, flags='DF'):
    # IP başlığını oluştur
    ip_packet = IP(dst=server_ip, ttl=ttl, flags=flags)  # IP başlığı oluşturuluyor
    
    # UDP taşıma katmanı (bunu eklemekte fayda var, aksi takdirde bağlantısız olur)
    udp_packet = UDP(dport=server_port, sport=12345)  # UDP başlığı
    
    # Paketle birleştir ve gönder
    packet = ip_packet/udp_packet/data
    send(packet)
    print(f"Paket gönderildi: {packet.summary()}")

# Şifreli veriyi gönderme
def send_encrypted_data(encrypted_data, server_ip, server_port):
    send_ip_packet(encrypted_data, server_ip, server_port, ttl=64, flags='DF')
    print("Şifreli veri gönderildi.")

# AES şifreleme işlemi
def encrypt_file(filename):
    with open(filename, 'rb') as file:
        file_data = file.read()

    # AES anahtarını ve IV'yi oluştur
    aes_key = os.urandom(32)  # 256-bit AES anahtarı
    iv = os.urandom(16)  # IV (Initialization Vector)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(file_data.ljust(len(file_data) + (16 - len(file_data) % 16), b'\0'))  # AES şifreleme
    return encrypted_data, aes_key, iv

# RSA ile AES anahtarını şifreleme
def encrypt_aes_key(aes_key):
    with open('public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

if __name__ == "__main__":
    # Dosya şifreleme ve veriyi gönderme
    filename = "test_files/ornek.txt"
    encrypted_data, aes_key, iv = encrypt_file(filename)
    encrypted_aes_key = encrypt_aes_key(aes_key)

    # Şifreli AES anahtarını ve dosya verisini gönderme
    send_encrypted_data(encrypted_aes_key, "127.0.0.1", 8080)
    send_encrypted_data(encrypted_data, "127.0.0.1", 8080)
    
    # IP başlıkları manipülasyonu örneği
    manipulate_ip_header("127.0.0.1")
    
    # Ping ile gecikme ölçümü örneği
    measure_latency("127.0.0.1")
