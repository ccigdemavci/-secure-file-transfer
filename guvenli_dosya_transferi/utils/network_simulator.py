import subprocess

def simulate_network_conditions(interface="eth0", delay="100ms", loss="10%"):
    print(f"➡️ Simülasyon başlatılıyor: {delay} gecikme, {loss} paket kaybı.")
    try:
        # tc ile netem ekle
        subprocess.run(
            ["sudo", "tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", delay, "loss", loss],
            check=True
        )
        print(f"✅ Simülasyon uygulandı: {interface} arayüzünde {delay} gecikme, {loss} paket kaybı.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Simülasyon eklenemedi: {e}")

def clear_network_conditions(interface="eth0"):
    print(f"➡️ Simülasyon temizleniyor...")
    try:
        subprocess.run(
            ["sudo", "tc", "qdisc", "del", "dev", interface, "root", "netem"],
            check=True
        )
        print(f"✅ Simülasyon temizlendi.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Simülasyon temizlenemedi: {e}")

if __name__ == "__main__":
    # Örnek kullanım
    simulate_network_conditions(interface="lo", delay="200ms", loss="5%")
    input("🔔 Test tamamlanınca Enter'a basın ve temizleme yapılacak...")
    clear_network_conditions(interface="lo")
