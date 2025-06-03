import subprocess

def run_iperf_test(server_ip="127.0.0.1", duration=10):
    print("iPerf3 testi başlatılıyor...")
    try:
        result = subprocess.run(
            ["iperf3", "-c", server_ip, "-t", str(duration)],
            capture_output=True,
            text=True
        )
        print("Test tamamlandı:\n")
        print(result.stdout)
    except Exception as e:
        print(f"Test sırasında hata oluştu: {e}")
