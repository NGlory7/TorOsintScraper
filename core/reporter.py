import os
import json
import html
from datetime import datetime

def generate_reports(results: list[dict], session_folder: str, exit_ip: str | None = None) -> tuple[str, str, str]:
    """
    Tor tarama sonuçlarını HTML Dashboard, TXT ve JSON formatlarında kaydeder.
    Orijinal kodla %100 uyumlu olarak results.json doğrudan sonuç listesini içerir.
    """
    os.makedirs(session_folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. JSON Çıktısı (Orijinal yapı: sonuç listesi)
    json_path = os.path.join(session_folder, "results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)

    # İstatistikler
    total_targets = len(results)
    live_targets = sum(1 for r in results if r.get("status") == "Up")
    total_emails = sum(len(r.get("analysis", {}).get("emails", [])) for r in results)
    total_btc = sum(len(r.get("analysis", {}).get("crypto_wallets", {}).get("btc", [])) for r in results)
    total_eth = sum(len(r.get("analysis", {}).get("crypto_wallets", {}).get("eth", [])) for r in results)
    total_xmr = sum(len(r.get("analysis", {}).get("crypto_wallets", {}).get("xmr", [])) for r in results)
    total_wallets = total_btc + total_eth + total_xmr
    total_onions = sum(len(r.get("analysis", {}).get("onion_links", [])) for r in results)

    # 2. TXT Özeti
    txt_path = os.path.join(session_folder, "scan_summary.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write("          TOR OSINT & THREAT INTELLIGENCE RAPORU\n")
        f.write(f" Tarama Zamanı : {timestamp}\n")
        f.write(f" Tor Çıkış IP  : {exit_ip or 'Tespit Edilemedi'}\n")
        f.write(f" Toplam Hedef  : {total_targets} (Aktif: {live_targets})\n")
        f.write(f" Kripto Cüzdan : {total_wallets} (BTC: {total_btc}, ETH: {total_eth}, XMR: {total_xmr})\n")
        f.write(f" E-Postalar    : {total_emails}\n")
        f.write("=" * 65 + "\n\n")

        for res in results:
            url = res.get("url", "")
            status = res.get("status", "Down")
            f.write(f"Hedef URL  : {url}\n")
            f.write(f"Durum      : {status}\n")

            if status == "Up":
                analysis = res.get("analysis", {})
                if analysis.get("title"):
                    f.write(f"Başlık     : {analysis.get('title')}\n")

                emails = analysis.get("emails", [])
                if emails:
                    f.write(f"E-Postalar : {', '.join(emails)}\n")

                wallets = analysis.get("crypto_wallets", {})
                for coin, w_list in wallets.items():
                    if w_list:
                        f.write(f"{coin.upper()} Cüzdan : {', '.join(w_list)}\n")

                onions = analysis.get("onion_links", [])
                if onions:
                    f.write(f"Onion Link : {len(onions)} adet tespit edildi.\n")

                if analysis.get("has_pgp"):
                    f.write("PGP Anahtar: PGP İmzası veya Genel Anahtarı Tespit Edildi!\n")
            else:
                f.write(f"Hata       : {res.get('error', 'Erişilemedi')}\n")

            f.write("-" * 50 + "\n")

    # 3. HTML Dashboard (XSS Korumalı & Modern Dark Tema)
    cards_html = []
    for res in results:
        url_raw = str(res.get("url", ""))
        url_safe = html.escape(url_raw)
        status = res.get("status", "Down")
        screenshot = res.get("screenshot")
        analysis = res.get("analysis", {})

        is_up = status == "Up"
        badge_class = "badge-success" if is_up else "badge-danger"
        status_text = "ÇEVRİMİÇİ" if is_up else "ÇEVRİMDIŞI"

        ss_abs = os.path.join(session_folder, "screenshots", screenshot) if screenshot else ""
        if screenshot and os.path.exists(ss_abs):
            img_tag = f'''<a href="screenshots/{html.escape(screenshot)}" target="_blank" rel="noopener">
                <img src="screenshots/{html.escape(screenshot)}" class="card-img" alt="{url_safe}" loading="lazy">
            </a>'''
        else:
            img_tag = '<div class="no-img">Ekran Görüntüsü Yok / Site Kapalı</div>'

        body_content = []
        if is_up:
            title = analysis.get("title", "")
            if title:
                body_content.append(f'<div class="card-title">{html.escape(title)}</div>')

            wallets = analysis.get("crypto_wallets", {})
            btc_list = wallets.get("btc", [])
            eth_list = wallets.get("eth", [])
            xmr_list = wallets.get("xmr", [])

            if btc_list or eth_list or xmr_list:
                pills = []
                for b in btc_list:
                    pills.append(f'<span class="pill pill-btc" title="Bitcoin">BTC: {html.escape(b)}</span>')
                for e in eth_list:
                    pills.append(f'<span class="pill pill-eth" title="Ethereum">ETH: {html.escape(e)}</span>')
                for x in xmr_list:
                    pills.append(f'<span class="pill pill-xmr" title="Monero">XMR: {html.escape(x)}</span>')
                body_content.append(f'<div class="section-box"><strong>💰 Kripto Cüzdanlar ({len(pills)}):</strong><br>{" ".join(pills)}</div>')

            emails = analysis.get("emails", [])
            if emails:
                e_pills = [f'<span class="pill pill-email">{html.escape(e)}</span>' for e in emails]
                body_content.append(f'<div class="section-box"><strong>📧 E-Postalar ({len(emails)}):</strong><br>{" ".join(e_pills)}</div>')

            onions = analysis.get("onion_links", [])
            if onions:
                body_content.append(f'<div class="section-box"><strong>🧅 Bulunan .onion Adresleri:</strong> {len(onions)} adet link tespit edildi.</div>')

            if analysis.get("has_pgp"):
                body_content.append('<div class="section-box pgp-alert">🔑 PGP Public Key / İmzası Tespit Edildi!</div>')
        else:
            err_msg = html.escape(str(res.get("error", "Bağlantı zaman aşımına uğradı veya servis kapalı.")))
            body_content.append(f'<div class="error-msg"><strong>Hata:</strong> {err_msg}</div>')

        card_markup = f'''
        <div class="card" data-status="{status.lower()}" data-search="{url_safe.lower()}">
            <div class="card-header">
                <span class="url-text">{url_safe}</span>
                <span class="badge {badge_class}">{status_text}</span>
            </div>
            {img_tag}
            <div class="card-body">
                {"".join(body_content)}
            </div>
        </div>
        '''
        cards_html.append(card_markup)

    all_cards = "\n".join(cards_html)

    html_content = f'''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tor OSINT Scraper - İstihbarat Paneli</title>
    <style>
        :root {{
            --bg-main: #0c0d14;
            --bg-card: #151724;
            --bg-header: #1d2033;
            --accent: #8e44ad;
            --accent-glow: #9b59b6;
            --text-main: #e2e8f0;
            --text-muted: #8c98a9;
            --border: #282c42;
            --success: #2ecc71;
            --danger: #e74c3c;
            --warning: #f39c12;
            --btc: #f7931a;
            --eth: #627eea;
            --xmr: #ff6600;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        .header-title {{
            font-size: 1.6rem;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header-meta {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 6px;
        }}
        .ip-pill {{
            background: rgba(142,68,173,0.25);
            border: 1px solid var(--accent);
            color: #d7bde2;
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: bold;
            font-family: monospace;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--accent-glow);
        }}
        .stat-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .search-box {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: #fff;
            padding: 12px 18px;
            border-radius: 8px;
            font-size: 0.95rem;
            margin-bottom: 24px;
        }}
        .search-box:focus {{ outline: 2px solid var(--accent); }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 24px rgba(0,0,0,0.5);
            border-color: var(--accent);
        }}
        .card-header {{
            background: var(--bg-header);
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
        }}
        .url-text {{
            font-size: 0.88rem;
            word-break: break-all;
            font-family: monospace;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: bold;
            white-space: nowrap;
        }}
        .badge-success {{ background: rgba(46,204,113,0.2); color: var(--success); border: 1px solid var(--success); }}
        .badge-danger  {{ background: rgba(231,76,60,0.2);  color: var(--danger);  border: 1px solid var(--danger);  }}
        .card-img {{
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-bottom: 1px solid var(--border);
            background: #000;
            display: block;
        }}
        .no-img {{
            height: 140px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
            background: #10121d;
            font-size: 0.85rem;
            border-bottom: 1px solid var(--border);
        }}
        .card-body {{
            padding: 14px 16px;
            font-size: 0.88rem;
            display: flex;
            flex-direction: column;
            gap: 10px;
            flex-grow: 1;
        }}
        .card-title {{
            font-weight: bold;
            color: #f1f2f6;
            font-size: 0.95rem;
        }}
        .section-box {{
            background: rgba(255,255,255,0.03);
            border-left: 3px solid var(--accent);
            padding: 8px 10px;
            border-radius: 4px;
            word-break: break-all;
        }}
        .pgp-alert {{
            border-left-color: var(--warning);
            background: rgba(243,156,18,0.1);
            color: #f39c12;
            font-weight: bold;
        }}
        .pill {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
            font-family: monospace;
            word-break: break-all;
        }}
        .pill-btc {{ background: rgba(247,147,26,0.2); color: #f7931a; border: 1px solid #f7931a; }}
        .pill-eth {{ background: rgba(98,126,234,0.2); color: #8fa3ff; border: 1px solid #627eea; }}
        .pill-xmr {{ background: rgba(255,102,0,0.2); color: #ff8533; border: 1px solid #ff6600; }}
        .pill-email {{ background: rgba(52,152,219,0.2); color: #74b9ff; border: 1px solid #3498db; }}
        .error-msg {{ color: var(--danger); font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                🧅 <strong>Tor OSINT Scraper & Threat Intelligence</strong>
            </div>
            <div class="header-meta">
                Tarama Tarihi: {timestamp} | Tor Çıkış Düğümü: <span class="ip-pill">{html.escape(exit_ip or "Bilinmiyor")}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num">{total_targets}</div>
                <div class="stat-label">Toplam Hedef</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--success);">{live_targets}</div>
                <div class="stat-label">Çevrimiçi Hedef</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--btc);">{total_wallets}</div>
                <div class="stat-label">Kripto Cüzdan</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #74b9ff;">{total_emails}</div>
                <div class="stat-label">E-Posta Adresi</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--accent-glow);">{total_onions}</div>
                <div class="stat-label">Keşfedilen .onion</div>
            </div>
        </div>

        <input type="text" id="searchInput" class="search-box" placeholder="URL, e-posta veya kripto cüzdan ara...">

        <div class="grid" id="cardGrid">
            {all_cards}
        </div>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const cards = document.querySelectorAll('.card');

        searchInput.addEventListener('input', (e) => {{
            const val = e.target.value.toLowerCase().trim();
            cards.forEach(card => {{
                const text = card.innerText.toLowerCase();
                if (text.includes(val)) {{
                    card.style.display = 'flex';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }});
    </script>
</body>
</html>'''

    html_path = os.path.join(session_folder, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return html_path, txt_path, json_path
