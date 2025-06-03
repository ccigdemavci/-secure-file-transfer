import socket
import os
import hashlib
from crypto.encrypt import encrypt_file  # AES şifreleme fonksiyonu
from key_generator import encrypt_aes_key  # RSA şifreleme fonksiyonu
from utils.token_utils import generate_token  # ✅ JWT Token üretimi

def calculate_sha256(filename):
    """Dosyanın SHA-256 hash'ini hesapla ve bytes olarak döndür."""
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

def send_file_secure(filename, server_ip, server_port, chunk_size=1024):
    # 1) Dosyayı AES ile şifrele
    encrypted_file, aes_key = encrypt_file(filename)

    # 2) AES anahtarını RSA ile şifrele
    encrypted_aes_key = encrypt_aes_key(aes_key)

    # 3) SHA-256 hash hesapla
    file_hash = calculate_sha256(encrypted_file)
    print(f"Dosyanın SHA-256 Hash'i: {file_hash.hex()}")

    # 4) JWT token üret
    token = generate_token("gonderici_kullanici")  # İstediğin kullanıcı adını ver
    token_bytes = token.encode()
    print(f"Token: {token}")

    # 5) Sunucuya bağlan
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # 6) AES anahtarını gönder (RSA ile şifrelenmiş)
    client_socket.send(encrypted_aes_key)

    # 7) Token uzunluğunu ve token'ı gönder
    client_socket.send(len(token_bytes).to_bytes(4, 'big'))
    client_socket.send(token_bytes)

    # 8) SHA-256 hash gönder
    client_socket.send(file_hash)

    # 9) Şifreli dosyayı gönder
    with open(encrypted_file, 'rb') as file:
        # 9.1) IV gönder
        iv = file.read(16)
        client_socket.send(iv)
        print(f"IV gönderildi: {iv.hex()}")

        # 9.2) Dosya parça sayısını gönder
        file_size = os.path.getsize(encrypted_file)
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        client_socket.send(total_chunks.to_bytes(4, 'big'))
        print(f"Toplam Parça Sayısı: {total_chunks}")

        # 9.3) Parça parça gönder
        chunk_number = 0
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            length = len(chunk)
            client_socket.send(length.to_bytes(4, 'big'))
            client_socket.send(chunk)
            print(f"Parça {chunk_number+1}/{total_chunks} gönderildi ({length} byte)")
            chunk_number += 1

    print(f"✅ {encrypted_file} başarıyla gönderildi.")
    client_socket.close()

# ✅ Kullanım
if __name__ == "__main__":
    send_file_secure("test_files/ornek.txt", "127.0.0.1", 8080, chunk_size=100)
