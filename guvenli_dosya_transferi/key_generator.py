from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# RSA Anahtar Çifti Üretme
def generate_rsa_keys():
    key = RSA.generate(2048)  # 2048 bitlik RSA anahtarı üret
    private_key = key.export_key()  # Private anahtar
    public_key = key.publickey().export_key()  # Public anahtar
    with open('private.pem', 'wb') as f:
        f.write(private_key)  # Private anahtar dosyaya kaydediliyor
    with open('public.pem', 'wb') as f:
        f.write(public_key)  # Public anahtar dosyaya kaydediliyor
    print("RSA Anahtarları başarıyla üretildi.")

# AES Anahtarını Public Anahtarla Şifreleme
def encrypt_aes_key(aes_key, public_key_file='public.pem'):
    # Public anahtarı yükle
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    # PKCS1_OAEP şifreleme algoritması ile AES anahtarını şifrele
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Şifrelenmiş AES anahtarını döndür
    return encrypted_aes_key

if __name__ == '__main__':
    generate_rsa_keys()
