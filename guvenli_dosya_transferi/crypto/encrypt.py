from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES şifreleme fonksiyonu
def encrypt_file(filename):
    key = get_random_bytes(16)  # Anahtar oluşturuluyor
    cipher = AES.new(key, AES.MODE_CBC)

    with open(filename, 'rb') as file:
        file_data = file.read()

    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    encrypted_filename = f"{filename}.enc"
    with open(encrypted_filename, 'wb') as enc_file:
        enc_file.write(cipher.iv)  # IV başa ekleniyor
        enc_file.write(encrypted_data)

    return encrypted_filename, key

# AES şifre çözme fonksiyonu
def decrypt_file(encrypted_filename, key):
    with open(encrypted_filename, 'rb') as file:
        iv = file.read(16)  # IV'yi oku
        encrypted_data = file.read()  # Şifreli veri

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    decrypted_filename = f"decrypted_{encrypted_filename}"
    with open(decrypted_filename, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    return decrypted_filename
