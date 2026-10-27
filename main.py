import asyncio
import os
import sys
import argparse
import warnings
from datetime import datetime

# Windows konsolunda UTF-8 desteği ve karakter bozulmasını engelleme
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

warnings.filterwarnings("ignore", category=DeprecationWarning)

from core.network import TorManager
from core.scanner import OSINTScanner
from core.reporter import generate_reports

# ANSI Renk Kodları
G = '\033[92m'  # Yeşil
R = '\033[91m'  # Kırmızı
B = '\033[94m'  # Mavi
Y = '\033[93m'  # Sarı
C = '\033[96m'  # Camgöbeği
W = '\033[0m'   # Reset

BANNER = f"""{C}
  _______           ____       _       _     _____                                
 |__   __|         / __ \\     (_)     | |   / ____|                               
    | | ___  _ __ | |  | | ___ _ _ __ | |_ | (___   ___ _ __ __ _ _ __   ___ _ __ 
    | |/ _ \\| '__|| |  | |/ __| | '_ \\| __| \\___ \\ / __| '__/ _` | '_ \\ / _ \\ '__|
    | | (_) | |   | |__| | (__| | | | | |_  ____) | (__| | | (_| | |_) |  __/ |   
    |_|\\___/|_|    \\____/ \\___|_|_| |_|\\__| |_____/ \\___|_|  \\__,_| .__/ \\___|_|   
                                                                  | |  v1.2.0    
                                                                  |_|  Onion Intel
{W}"""

def load_targets(target_file: str, single_url: str | None = None) -> list[str]:
    """Hedef URL listesini dosyadan veya CLI parametresinden yükler."""
    if single_url:
        return [single_url.strip()]

    if not os.path.exists(target_file):
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("# Tor OSINT Scraper - Hedef URL Listesi\n")
            f.write("https://check.torproject.org\n")
            f.write("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfima3ogtwv7v64yyad.onion\n")
        print(f"{Y}[!] '{target_file}' bulunamadı, varsayılan örnek dosya oluşturuldu.{W}")
        return [
            "https://check.torproject.org",
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfima3ogtwv7v64yyad.onion"
        ]

    with open(target_file, "r", encoding="utf-8") as f:
        targets = [
            line.strip() for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    return targets

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Tor Ağı Üzerinde Otomatik OSINT, Kripto Cüzdan ve İstihbarat Tarayıcısı",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--targets", default="targets.txt", help="Hedef URL'lerin bulunduğu dosya yolu")
    parser.add_argument("-u", "--url", help="Tek bir hedef URL taramak için")
    parser.add_argument("-p", "--proxy", help="Özel SOCKS5 proxy adresi (örn: socks5://127.0.0.1:9050)")
    parser.add_argument("-o", "--output", default="scans", help="Raporların kaydedileceği ana dizin")
    parser.add_argument("-c", "--concurrency", type=int, default=3, help="Eşzamanlı taranacak sekme sayısı")
    parser.add_argument("--timeout", type=int, default=90, help="Sayfa yükleme zaman aşımı süresi (saniye)")
    parser.add_argument("--skip-tor-check", action="store_true", help="Tor bağlantı doğrulamasını atla (Clearnet testleri için)")
    return parser.parse_args()

async def async_main(args):
    targets = load_targets(args.targets, args.url)
    if not targets:
        print(f"{R}[!] Taranacak hiçbir hedef bulunamadı. Çıkış yapılıyor.{W}")
        return

    # Tor Bağlantı Kontrolü
    tor = TorManager(proxy_addr=args.proxy)
    if not args.skip_tor_check:
        connected = await tor.check_connection()
        if not connected:
            print(f"\n{R}[!] Tor ağına bağlanılamadı.{W}")
            print(f"{Y}[*] Çözüm Adımları:{W}")
            print("  1. Bilgisayarınızda Tor Browser'ı başlatıp ağa bağlanın (Varsayılan port: 9150).")
            print("  2. Ya da arka planda 'tor' servisini çalıştırın (Varsayılan port: 9050).")
            print("  3. Clearnet testi yapıyorsanız '--skip-tor-check' parametresini kullanın.\n")
            return
    else:
        print(f"{Y}[*] Tor bağlantı kontrolü kullanıcı parametresiyle atlandı (--skip-tor-check).{W}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_folder = os.path.join(os.path.abspath(args.output), f"scan_{timestamp}")
    os.makedirs(session_folder, exist_ok=True)

    print(f"\n{B}[*] {len(targets)} hedef yüklendi. Arşiv: {session_folder}{W}")

    # Tarama İşlemi
    scanner = OSINTScanner(
        targets=targets,
        tor_manager=tor,
        concurrency=args.concurrency,
        timeout_sec=args.timeout,
        use_proxy=not args.skip_tor_check
    )
    results = await scanner.run(session_folder)

    # Terminal Çıktısı (Orijinal yapıya uygun)
    print("\n" + "-" * 15 + " TARAMA SONUÇLARI " + "-" * 15)
    for res in results:
        is_up = res.get("status") == "Up"
        status_tag = f"{G}[UP]{W}" if is_up else f"{R}[DOWN]{W}"
        print(f"{status_tag} {res['url']} -> {res.get('status')}")
        if is_up:
            hints = res.get("analysis", {}).get("osint", {})
            emails = hints.get("emails", [])
            wallets = hints.get("crypto_wallets", {})
            if emails:
                print(f"   {Y}[+] E-postalar: {len(emails)} adet{W}")
            btc = wallets.get("btc", [])
            if btc:
                print(f"   {Y}[+] BTC Cüzdanlar: {len(btc)} adet{W}")
            eth = wallets.get("eth", [])
            if eth:
                print(f"   {Y}[+] ETH Cüzdanlar: {len(eth)} adet{W}")
            xmr = wallets.get("xmr", [])
            if xmr:
                print(f"   {Y}[+] XMR Cüzdanlar: {len(xmr)} adet{W}")
            onions = hints.get("onion_links", [])
            if onions:
                print(f"   {Y}[+] Bulunan Onion Bağlantıları: {len(onions)} adet{W}")

    print("-" * 48)

    # Raporlama
    print(f"\n{B}[*] Raporlar derleniyor...{W}")
    html_path, txt_path, json_path = generate_reports(
        results=results,
        session_folder=session_folder,
        exit_ip=tor.exit_ip
    )

    print(f"\n{G}{'=' * 60}{W}")
    print(f"{G} [+] TARAMA BAŞARIYLA TAMAMLANDI {W}")
    print(f"{Y} [+] HTML Dashboard : {W}{html_path}")
    print(f"{Y} [+] TXT Özeti      : {W}{txt_path}")
    print(f"{Y} [+] JSON Veri Seti : {W}{json_path}")
    print(f"{G}{'=' * 60}{W}\n")

def main():
    print(BANNER)
    args = parse_arguments()

    try:
        if sys.platform == 'win32' and sys.version_info < (3, 14):
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            except Exception:
                pass

        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print(f"\n\n{R}[!] İşlem kullanıcı tarafından iptal edildi (Ctrl+C).{W}")
        print(f"{Y}[*] Güvenli şekilde sonlandırıldı.{W}")
        sys.exit(0)

if __name__ == "__main__":
    main()
