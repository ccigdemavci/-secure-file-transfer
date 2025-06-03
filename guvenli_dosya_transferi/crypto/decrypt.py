from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os  # os modülünü import edin

def decrypt_file(encrypted_file_path, aes_key, iv):
    # AES çözme işlemi
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    with open(encrypted_file_path, 'rb') as file:
        ciphertext = file.read()  # Şifreli veriyi oku
    
    # AES çözme
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Çözülmüş veriyi dosyaya yaz
    decrypted_file_path = f"decrypted_{os.path.basename(encrypted_file_path)}"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)
    
    print(f"{decrypted_file_path} başarıyla çözüldü.")
