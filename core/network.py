import socket
import httpx

class TorManager:
    """
    Tor SOCKS5 proxy bağlantısını yönetir ve Tor ağ durumunu doğrular.
    """
    DEFAULT_PROXY = "socks5://127.0.0.1:9150"

    def __init__(self, proxy_addr: str | None = None):
        self.proxy_addr = proxy_addr or self.detect_proxy()
        self.exit_ip: str | None = None
        self.is_connected: bool = False

    def detect_proxy(self) -> str:
        """Sistemde 9150 (Tor Browser) veya 9050 (Tor Servisi) portlarını kontrol eder."""
        for port in [9150, 9050]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", port))
                    return f"socks5://127.0.0.1:{port}"
            except Exception:
                continue
        # Varsayılan olarak Tor Browser portuna ayarla
        return self.DEFAULT_PROXY

    async def check_connection(self) -> bool:
        """Tor bağlantısını check.torproject.org üzerinden resmi olarak test eder."""
        print(f"[*] Tor proxy kontrol ediliyor: {self.proxy_addr}...")
        try:
            async with httpx.AsyncClient(proxy=self.proxy_addr, timeout=15.0) as client:
                resp = await client.get("https://check.torproject.org")
                if "Congratulations" in resp.text:
                    self.is_connected = True
                    print("[+] [BAŞARILI] Tor bağlantısı aktif!")

                    # Çıkış IP'sini tespit etmeye çalış
                    try:
                        api_resp = await client.get("https://check.torproject.org/api/ip", timeout=5.0)
                        if api_resp.status_code == 200:
                            data = api_resp.json()
                            self.exit_ip = data.get("IP")
                            if self.exit_ip:
                                print(f"    [+] Tor Çıkış Düğümü IP: {self.exit_ip}")
                    except Exception:
                        pass

                    return True

                print("[-] [UYARI] Proxy yanıt verdi ancak Tor ağı algılanamadı.")
                return False

        except Exception as e:
            print(f"[-] [KRİTİK] Tor bağlantı hatası: {e}")
            return False
