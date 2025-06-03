# Güvenli Dosya Transferi Sistemi  

Bu proje, AES ve RSA şifreleme algoritmalarını kullanarak güvenli dosya transferi sağlayan, IP başlığı manipülasyonu ve ağ performans analizi yapan kapsamlı bir Python projesidir.  

## 📌 Proje Nasıl Çalışır?  

1️⃣ Gönderici tarafında bir dosya AES CBC modunda şifrelenir. Her dosya için farklı bir IV üretilir ve şifreli verinin başına eklenir.  
2️⃣ AES anahtarı RSA public key ile şifrelenir.  
3️⃣ Şifrelenmiş AES anahtarı, JWT token ve SHA-256 hash hesaplanır.  
4️⃣ Şifreli dosya parçalara ayrılır ve TCP bağlantısı üzerinden alıcıya gönderilir.  
5️⃣ Alıcı tarafında RSA private key ile AES anahtarı çözülür.  
6️⃣ JWT token doğrulanır.  
7️⃣ SHA-256 hash kontrolü yapılarak dosyanın bozulmadığı doğrulanır.  
8️⃣ Dosya parçaları sıralı bir şekilde alınır ve birleştirilir.  
9️⃣ AES CBC ile şifre çözüldükten sonra dosya kullanılabilir hale gelir.  
🔟 Ayrıca, IP başlığı manipülasyonu ve fragmentasyon işlemleri ile IP seviyesinde protokol analizi yapılır.   

## 🛠️ Kullanılan Teknolojiler  
- **Python**: Projenin temel dili.  
- **PyCryptodome**: AES ve RSA şifreleme.  
- **PyJWT**: JSON Web Token üretimi ve doğrulama.  
- **Scapy**: IP başlığı manipülasyonu ve paket enjeksiyonu.  
- **Wireshark**: Trafik analizi ve paket inceleme.  
- **iPerf3**: Bant genişliği ve bağlantı hızı testi.  
- **tc (traffic control)**: Paket kaybı ve gecikme simülasyonu (Linux/Mac teorik).  
- **hashlib**: SHA-256 hash hesaplama.  
- **socket**: TCP bağlantısı oluşturma.  
- **subprocess**: Dış komutları (iperf3 ve tc) çalıştırma.  
- **os**: Dosya işlemleri.

  ## 📂 Projede Neler Yaptım?  

✅ **AES CBC Şifreleme ve Çözme (encrypt.py, decrypt.py)**  
- Dosya AES CBC modunda şifrelenir ve IV başa eklenir.  
- Alıcı tarafında IV kullanılarak şifre çözülür.  

✅ **RSA Anahtar Çifti Üretimi (key_generator.py)**  
- RSA public/private anahtar çiftleri üretilir.  
- AES anahtarı RSA ile şifrelenip güvenli şekilde gönderilir.  

✅ **JWT Token ile Kimlik Doğrulama (token_utils.py)**  
- Kullanıcı kimliği doğrulamak için JWT token üretilir ve süresi kontrol edilir.  

✅ **SHA-256 ile Dosya Bütünlük Kontrolü (sender.py, receiver.py)**  
- Dosya hash’lenerek gönderici ve alıcı tarafında bütünlük kontrolü yapılır.  

✅ **Dosya Transferi (sender.py, receiver.py)**  
- Şifreli dosya TCP bağlantısı ile parça parça gönderilir ve alıcıda birleştirilir.  
- Parça sayısı ve uzunluğu TCP bağlantısında bildirilerek hatasız birleştirme sağlanır.  

✅ **IP Başlığı Manipülasyonu ve Fragmentasyon (ip.header_operation.py, ip.fegmentatin.py)**  
- IP başlığı TTL, fragment offset ve checksum gibi alanlar elle ayarlanarak protokol analizi yapılır.  

✅ **Ağ Performansı Testleri (analyzer.py)**  
- iPerf3 ile bant genişliği ölçümü yapılır.  
- Sunucu terminalinde `iperf3 -s`, istemci tarafında Python `analyzer.py` kullanılır.  

✅ **tc ile Gecikme ve Paket Kaybı Simülasyonu (network_simulator.py)**  
- Linux/Mac üzerinde teorik olarak yazılmıştır (sudo izni gerektirir).  

✅ **Paket Enjeksiyonu Testi (packet_injector.py)**  
- Sahte UDP paketleri gönderilerek saldırıya karşı dayanıklılık test edilmiştir.  

✅ **Wireshark Analizi**  
- Tüm transfer trafiği Wireshark ile izlenerek AES/RSA sayesinde paketlerin şifresiz çözülemediği test edilmiştir.  

## 📂 Proje Yapısı  
guvenli_dosya_transferi/
│
├── sender.py
├── receiver.py
├── key_generator.py
├── crypto/
│ ├── encrypt.py
│ └── decrypt.py
├── utils/
│ └── token_utils.py
├── network/
│ ├── packet_builder.py
│ ├── ip.header_operation.py
│ ├── ip.fegmentatin.py
│ ├── packet_injector.py
│ ├── analyzer.py
│ └── network_simulator.py
└── test_files/
└── ornek.txt



## 🚀 Projeyi Çalıştırmak  

1️⃣ Kütüphaneleri yükleyin:  

pip install pycryptodome scapy pyjwt socket hashlib subprocess os

2️⃣ RSA anahtar çiftlerini üretin:

python key_generator.py

3️⃣ Gönderici tarafında dosya gönderimi başlatın:

python sender.py

4️⃣ Alıcı tarafında dosya alımını başlatın:

python receiver.py

5️⃣ iPerf3 sunucu başlatın (farklı terminalde):

iperf3 -s
