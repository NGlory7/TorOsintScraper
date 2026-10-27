# 🧅 Tor OSINT Scraper & Threat Intelligence Suite (v1.2.0)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tor Network](https://img.shields.io/badge/network-Tor%20SOCKS5-purple.svg)](https://www.torproject.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Playwright](https://img.shields.io/badge/engine-playwright-green.svg)](https://playwright.dev/)

**Tor OSINT Scraper**, Tor (The Onion Router) ağı ve Dark Web üzerindeki `.onion` veya clearnet servisleri üzerinde otomatik keşif, adli bilişim incelemesi (görsel arşivleme) ve siber tehdit istihbaratı (OSINT) toplayan modüler bir güvenlik aracıdır.

Tüm istekler **SOCKS5** protokolü üzerinden Tor ağına yönlendirilir ve DNS sızıntılarını (DNS Leak) önlemek üzere özel proxy kuralları uygulanır.

---

## ⚡ Temel Özellikler

- 🛡️ **Otomatik Tor Proxy Tespiti:** Sistemdeki aktif Tor portlarını (Port 9150 `Tor Browser` ve Port 9050 `Tor Daemon`) otomatik tespit eder ve Tor çıkış düğümü (Exit Node) IP adresini doğrular.
- 📸 **Görsel Kanıt Toplama (Headless Recon):** Taranan her gizli servisin tam çözünürlüklü ekran görüntüsünü Chromium tarayıcısı üzerinden alarak arşivler.
- 💰 **Kripto Varlık ve Cüzdan Madenciliği:** Sayfa kaynaklarında ve metinlerde yer alan kripto cüzdan adreslerini yalancı pozitifleri (false-positive) eleyen desenlerle tespit eder:
  - **Bitcoin (BTC):** Legacy (`1...`), Script (`3...`) ve SegWit/Bech32 (`bc1...`)
  - **Ethereum (ETH):** Standart `0x` adresleri
  - **Monero (XMR):** Standart Dark Web gizlilik cüzdanları (`4...`)
- 📧 **İletişim & Kimlik Tespiti:**
  - E-posta adresleri (resim ve geçersiz uzantılardan arındırılmış)
  - Telegram kanalları ve kullanıcı adları (`t.me/...`)
  - XMPP / Jabber hesapları (`@exploit.im`, `@jabber.*`, `@calyx.net` vb.)
  - PGP Genel Anahtarları (Public Key Block) ve dijital imzalar
- 🧅 **Onion Ağ Haritalama:** Sayfa içerisinde referans verilen diğer `.onion` (v2 ve v3) bağlantılarını toplar.
- 🚦 **Akıllı Eşzamanlılık (Concurrency Control):** Tor ağının dar bant genişliğini tıkamamak ve SOCKS bağlantı kopmalarını önlemek için asenkron Semaphore ile kontrollü sekme yönetimi sağlar.
- 📊 **Etkileşimli Dark Mode Dashboard:** Taranan siteleri, açık/kapalı durumlarını, kripto bulgularını ve ekran görüntülerini tek bir arama/filtreleme destekli HTML panelinde sunar. Ayrıca yapılandırılmış **JSON** ve **TXT** raporları üretir.

---

## 🚀 Kurulum

### 1. Depoyu Klonlayın
```bash
git clone https://github.com/NGlory7/TorOsintScraper.git
cd TorOsintScraper
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 3. Tarayıcı Motorlarını Kurun
```bash
playwright install chromium
```

### 4. Tor Ağını Başlatın
Aracın Tor ağına bağlanabilmesi için sisteminizde **Tor Browser**'ın açık ve ağa bağlı olması ya da arka planda bir **Tor servisinin** çalışıyor olması gerekmektedir:
- **Tor Browser Kullanıcıları:** Tarayıcıyı açın ve *"Connect"* butonuna tıklayın (Varsayılan SOCKS5 portu: `9150`).
- **Linux / Standalone Tor:** `sudo systemctl start tor` komutunu çalıştırın (Varsayılan SOCKS5 portu: `9050`).

---

## 💻 Kullanım

### Temel Tarama (targets.txt üzerinden)
`targets.txt` dosyasına taranmasını istediğiniz `.onion` veya clearnet URL'lerini her satıra bir adet gelecek şekilde ekleyin, ardından aracı çalıştırın:
```bash
python main.py
```

### CLI / Terminal Parametreleri ile Çalıştırma
```bash
# Tek bir onion sitesini doğrudan tarama
python main.py -u http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfima3ogtwv7v64yyad.onion

# Özel proxy adresi ve farklı bir hedef dosyası belirterek tarama
python main.py -t my_targets.txt -p socks5://127.0.0.1:9050 -c 4

# Clearnet sitelerini Tor kontrolü olmadan hızlıca test etme
python main.py -u https://example.com --skip-tor-check
```

### Parametre Listesi

| Parametre | Kısa Yol | Varsayılan | Açıklama |
|---|---|---|---|
| `--targets` | `-t` | `targets.txt` | Hedef URL'lerin bulunduğu dosya yolu |
| `--url` | `-u` | `None` | Tek bir hedef URL taramak için |
| `--proxy` | `-p` | `Otomatik (9150/9050)` | Özel SOCKS5 proxy adresi |
| `--output` | `-o` | `scans` | Raporların ve oturumların kaydedileceği ana dizin |
| `--concurrency` | `-c` | `3` | Eşzamanlı taranacak tarayıcı sekmesi sayısı |
| `--timeout` | | `60` | Sayfa yükleme zaman aşımı süresi (saniye) |
| `--skip-tor-check`| | `False` | Tor bağlantı testini atlar (Clearnet için) |

---

## 📂 Proje Yapısı

```text
TorOsintScraper/
├── core/
│   ├── __init__.py         # Paket tanımlayıcısı
│   ├── network.py          # Tor SOCKS5 proxy ve çıkış IP yöneticisi
│   ├── analyzer.py         # Kripto cüzdan, e-posta ve PGP regex analiz motoru
│   ├── scanner.py          # Playwright ile Tor üzerinden asenkron tarayıcı
│   └── reporter.py         # HTML Dashboard, TXT ve JSON raporlayıcı
├── scans/                  # Tarama oturumları ve ekran görüntüleri (Gitignore)
├── .gitattributes          # Satır sonu ve dosya tipi normalizasyonu
├── .gitignore              # Geçici dosyaları yoksayma kuralları
├── LICENSE                 # MIT Lisansı
├── main.py                 # CLI ve ana uygulama orkestratörü
├── README.md               # Proje dökümantasyonu
├── requirements.txt        # Python paket bağımlılıkları
└── targets.txt             # Örnek hedef listesi
```

---

## 📊 Rapor Çıktıları

Her tarama işlemi tamamlandığında `scans/scan_<timestamp>/` klasörü altında şu çıktılar oluşturulur:

1. **`index.html`**: Arama ve filtreleme özellikli görsel Dark Mode dashboard.
2. **`screenshots/`**: Taranan sitelerin tam sayfa ekran görüntüleri.
3. **`scan_summary.txt`**: Terminal dostu detaylı metin analizi.
4. **`results.json`**: Diğer güvenlik araçları veya SIEM sistemleri için yapılandırılmış JSON verisi.

---

## ⚖️ Yasal Uyarı

Bu araç yalnızca **adli bilişim analizleri, siber tehdit istihbaratı (CTI), yetkili güvenlik testleri ve eğitim amaçları** için tasarlanmıştır. Yetkisiz ağlara veya yasa dışı servislerin kötüye kullanımına yönelik faaliyetlerden doğacak tüm yasal sorumluluk tamamen kullanıcıya aittir.

---

## 📜 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.
