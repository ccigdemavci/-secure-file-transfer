import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from crypto.decrypt import decrypt_file
from utils.token_utils import verify_token  # ✅ Token doğrulama

def recvall(sock, n):
    """Tam olarak n byte oku veya None dön."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def calculate_sha256(filename):
    """SHA-256 hash hesapla ve bytes olarak döndür."""
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

def receive_file_secure(server_ip, server_port, save_path, private_key_file='private.pem'):
    # 1) Dinlemeye başla
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print(f"Dinlemede: {server_ip}:{server_port}")
    client_socket, addr = server_socket.accept()
    print(f"Bağlandı: {addr}")

    # 2) RSA ile şifrelenmiş AES anahtarını al ve çöz
    private_key = RSA.import_key(open(private_key_file, 'rb').read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    key_size = private_key.size_in_bytes()
    encrypted_aes_key = recvall(client_socket, key_size)
    if not encrypted_aes_key:
        print("❌ AES anahtarı alınamadı.")
        client_socket.close()
        server_socket.close()
        return
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print(f"AES Anahtarı Çözüldü: {aes_key.hex()}")

    # ✅ 2.5) Token'ı al ve doğrula
    token_length_bytes = recvall(client_socket, 4)
    if not token_length_bytes:
        print("❌ Token uzunluğu alınamadı.")
        client_socket.close()
        server_socket.close()
        return
    token_length = int.from_bytes(token_length_bytes, 'big')
    token_bytes = recvall(client_socket, token_length)
    if not token_bytes:
        print("❌ Token alınamadı.")
        client_socket.close()
        server_socket.close()
        return

    token = token_bytes.decode()
    valid, info = verify_token(token)
    if not valid:
        print(f"❌ Token doğrulanamadı: {info}")
        client_socket.close()
        server_socket.close()
        return
    else:
        print(f"✅ Token doğrulandı, kullanıcı: {info}")

    # 3) SHA-256 hash değerini al (32 byte)
    expected_hash = recvall(client_socket, 32)
    if not expected_hash:
        print("❌ SHA-256 hash alınamadı.")
        client_socket.close()
        server_socket.close()
        return
    print(f"Gelen SHA-256 Hash: {expected_hash.hex()}")

    # 4) IV'yi al
    iv = recvall(client_socket, AES.block_size)
    if not iv:
        print("❌ IV alınamadı.")
        client_socket.close()
        server_socket.close()
        return
    print(f"IV Alındı: {iv.hex()}")

    # 5) Toplam parça sayısını al
    total_chunks_bytes = recvall(client_socket, 4)
    if not total_chunks_bytes:
        print("❌ Parça sayısı alınamadı.")
        client_socket.close()
        server_socket.close()
        return
    total_chunks = int.from_bytes(total_chunks_bytes, 'big')
    print(f"Toplam Parça Sayısı: {total_chunks}")

    # 6) IV'yi ve parçaları dosyaya sırayla yaz
    with open(save_path, 'wb') as f:
        f.write(iv)  # ✅ IV'yi başta yaz
        for i in range(total_chunks):
            length_bytes = recvall(client_socket, 4)
            if not length_bytes:
                print(f"❌ {i+1}. parça uzunluk bilgisi alınamadı.")
                break
            chunk_length = int.from_bytes(length_bytes, 'big')
            chunk = recvall(client_socket, chunk_length)
            if not chunk:
                print(f"❌ {i+1}. parça alınamadı.")
                break
            f.write(chunk)
            print(f"Parça {i+1}/{total_chunks} alındı ({chunk_length} byte)")
    print(f"Şifreli dosya alındı: {save_path}")

    # 7) SHA-256 doğrulama
    actual_hash = calculate_sha256(save_path)
    print(f"Hesaplanan SHA-256 Hash: {actual_hash.hex()}")
    if expected_hash == actual_hash:
        print("✅ SHA-256 doğrulaması başarılı. Dosya bozulmamış.")

        # 8) AES ile deşifre et ve kaydet
        decrypt_file(save_path, aes_key, iv)
        print(f"Dosya başarıyla çözüldü.")
    else:
        print("❌ SHA-256 doğrulaması başarısız! Dosya bozulmuş olabilir.")

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    receive_file_secure("127.0.0.1", 8080, "received_file.enc")
