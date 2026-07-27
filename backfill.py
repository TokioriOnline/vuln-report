"""
backfill.py - スタンドアロン版
collect_vulns.pyに依存せず単独で動作します
7月初めからの過去データを遡及生成するスクリプト
Macのターミナルで一度だけ実行してください
"""

import requests
import json
import os
from datetime import datetime, timedelta

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 設定
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DOCS_DIR = "docs"
FEATURE_DIR = "docs/feature"

BACKFILL_DATES = [
    "2026-07-06",
    "2026-07-13",
    "2026-07-20",
]

MAJOR_PRODUCTS = [
    "windows", "exchange", "apache", "cisco",
    "fortinet", "vmware", "citrix", "ivanti",
    "palo alto", "juniper", "f5", "sharepoint",
    "outlook", "office", "chrome", "firefox",
    "adobe", "log4j", "spring", "confluence",
    "gitlab", "github", "jenkins", "netscaler",
    "junos", "bigip", "pulse", "sonicwall"
]

MAJOR_THREATS = [
    "ransomware", "remote code execution",
    "zero-day", "0-day", "nation-state",
    "supply chain", "unauthenticated"
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# KEV全件取得
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def fetch_all_kev():
    """CISA KEV全件取得(複数の方法を試す)"""

    urls = [
        # メインURL
        (
            "https://www.cisa.gov/sites/default"
            "/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
        # 代替URL
        (
            "https://www.cisa.gov/sites/default"
            "/files/csv/"
            "known_exploited_vulnerabilities.json"
        ),
    ]

    for url in urls:
        for verify in [True, False]:
            try:
                resp = requests.get(
                    url, timeout=30,
                    verify=verify,
                    headers={{
                        "User-Agent": (
                            "Mozilla/5.0 "
                            "(Macintosh; Intel Mac OS X)"
                        )
                    }}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data["vulnerabilities"]
                    print(
                        f"KEV取得成功: {len(vulns)}件"
                    )
                    return vulns
            except Exception as e:
                print(f"試行失敗: {e}")
                continue

    print("❌ KEV取得失敗")
    return []

def filter_kev_by_week(
    all_kev, week_start_str
):
    """指定週のKEVを抽出"""
    start = datetime.strptime(
        week_start_str, "%Y-%m-%d"
    )
    end = start + timedelta(days=7)
    result = [
        v for v in all_kev
        if start <= datetime.strptime(
            v["dateAdded"], "%Y-%m-%d"
        ) < end
    ]
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 重要度・特集判定
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_major(vuln):
    text = (
        vuln.get("product", "") + " " +
        vuln.get("shortDescription", "") + " " +
        vuln.get("vendorProject", "")
    ).lower()
    return (
        any(p in text for p in MAJOR_PRODUCTS) or
        any(t in text for t in MAJOR_THREATS)
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CSS(共通)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_css():
    return """
        body {
            font-family: 'Helvetica Neue', sans-serif;
            max-width: 900px; margin: auto;
            padding: 20px; background: #f5f5f5;
            color: #333;
        }
        h1 { color: #1a1a2e; }
        h2 {
            border-left: 4px solid #333;
            padding-left: 10px; margin-top: 30px;
        }
        .card {
            background: white; border-radius: 8px;
            padding: 15px 20px; margin: 10px 0;
        }
        .card.critical {
            border-left: 5px solid #cc0000;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px; border-radius: 12px;
            font-size: 0.85em; font-weight: bold;
            margin-bottom: 8px;
        }
        .badge-critical, .badge-CRITICAL {
            background: #cc0000; color: white;
        }
        .badge-高 { background: #ff6600; color: white; }
        .badge-中 { background: #ffaa00; color: white; }
        .badge-低 { background: #009900; color: white; }
        .summary-box {
            background: #1a1a2e; color: white;
            border-radius: 8px; padding: 20px;
            margin: 20px 0;
        }
        .summary-box h2 {
            color: white; border-color: white;
        }
        .summary-box table {
            width: 100%; border-collapse: collapse;
        }
        .summary-box td { padding: 8px; }
        .persistent-critical {
            background: #fff0f0;
            border: 1px solid #ffcccc;
            border-radius: 8px;
            padding: 16px 20px; margin: 10px 0;
        }
        .days-since {
            font-size: 0.8em; color: #cc0000;
            margin-top: 4px;
        }
        .update-time {
            background: #e8f4f8; padding: 10px 15px;
            border-radius: 5px; margin-bottom: 20px;
            font-size: 0.9em;
        }
        .disclaimer {
            background: #fff8e1;
            border-left: 4px solid #ffaa00;
            padding: 15px 20px; margin: 30px 0;
            border-radius: 4px; font-size: 0.9em;
        }
        footer {
            text-align: center; margin-top: 40px;
            padding: 20px; color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
        table {
            width: 100%; border-collapse: collapse;
            background: white; border-radius: 8px;
        }
        th, td {
            padding: 10px; border: 1px solid #eee;
            text-align: center;
        }
        th { background: #1a1a2e; color: white; }
        tr:hover { background: #f5f5f5; }
        a { color: #0066cc; }
    """


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 特集ページ生成
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_feature_page(vuln):
    """重大脆弱性の特集ページを生成"""
    os.makedirs(FEATURE_DIR, exist_ok=True)

    cve_id = vuln["cveID"]
    safe_id = cve_id.replace("/", "-").replace(
        ":", "-").replace(" ", "-")
    filepath = f"{FEATURE_DIR}/{safe_id}.html"

    product = vuln.get("product", "")
    vendor = vuln.get("vendorProject", "")
    description = vuln.get("shortDescription", "")
    date_added = vuln.get("dateAdded", "")
    due_date = vuln.get("dueDate", "")
    product_lower = product.lower()
    desc_lower = description.lower()

    # 製品別影響・対策
    if "windows" in product_lower or \
       "microsoft" in product_lower:
        impact = (
            "Windows製品の脆弱性は中小企業への"
            "影響が特に広範です。社内PC・サーバー・"
            "リモートデスクトップ環境が攻撃対象となります。"
        )
        mitigation = [
            "Windows Updateを即時実行する",
            "自動更新が有効か全端末を確認",
            "RDPの不要な公開を停止",
            "EDRやウイルス対策の定義ファイルを更新"
        ]
    elif any(p in product_lower for p in
             ["cisco", "fortinet", "vpn",
              "netscaler", "ivanti", "pulse",
              "sonicwall"]):
        impact = (
            "VPN機器・ネットワーク機器の脆弱性は"
            "リモートワーク環境で特に深刻です。"
            "社内ネットワーク全体が危険にさらされます。"
        )
        mitigation = [
            "ファームウェアを即時更新",
            "管理画面へのアクセスをIPアドレスで制限",
            "不審な接続ログを確認",
            "MFA(多要素認証)を有効化"
        ]
    elif any(p in product_lower for p in
             ["apache", "iis", "nginx",
              "tomcat", "log4j"]):
        impact = (
            "Webサーバーの脆弱性は自社Webサイトや"
            "社内システムへの不正アクセス・改ざんに"
            "つながります。外部委託先も含め確認が必要です。"
        )
        mitigation = [
            "Webサーバーを最新版に更新",
            "外部委託先に対応状況を確認",
            "WAFの導入を検討",
            "サーバーログに不審なアクセスがないか確認"
        ]
    elif any(p in product_lower for p in
             ["exchange", "outlook",
              "office", "365", "sharepoint"]):
        impact = (
            "メール・グループウェアの脆弱性は"
            "ビジネスメール詐欺や情報漏洩の入口となります。"
        )
        mitigation = [
            "Microsoft Updateを即時適用",
            "メールフィルタリングの設定を強化",
            "不審なメールの報告フローを社内で周知",
            "管理者アカウントのMFAを確認"
        ]
    else:
        impact = (
            "この脆弱性が自社システムで使用している"
            "ソフトウェアに該当しないか確認してください。"
        )
        mitigation = [
            "影響を受けるバージョンを確認",
            "ベンダーの公式情報でパッチを確認",
            "パッチがない場合は回避策を適用",
            "ITベンダーや専門家に相談"
        ]

    ransomware_note = ""
    if "ransomware" in desc_lower:
        ransomware_note = """
        <div style="background:#fff0f0;
            border-left:4px solid #cc0000;
            padding:16px; border-radius:4px;
            margin:16px 0;">
            <h3 style="color:#cc0000;">
                ⚠️ ランサムウェアによる悪用が
                報告されています
            </h3>
            <p>
                この脆弱性はランサムウェア攻撃グループに
                よる悪用が確認されています。<br>
                <strong>バックアップがオフラインで
                保管されているか今すぐ確認してください。
                </strong>
            </p>
        </div>"""

    mitigation_html = "".join(
        f"<li style='padding:10px 0;"
        f"border-bottom:0.5px solid #eee;'>"
        f"✓ {m}</li>"
        for m in mitigation
    )

    try:
        display_date = datetime.strptime(
            date_added, "%Y-%m-%d"
        ).strftime("%Y年%m月%d日")
    except Exception:
        display_date = date_added

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>【特集】{cve_id} {product} |
    Tokiori Online</title>
    <style>{get_css()}</style>
</head>
<body>
    <p>
        <a href="../index.html">
            ← 最新レポートに戻る
        </a> |
        <a href="../archive.html">
            📚 アーカイブ一覧
        </a>
    </p>

    <div style="background:#1a1a2e;color:white;
        border-radius:8px;padding:24px;
        margin-bottom:20px;">
        <span style="background:#cc0000;
            color:white;padding:4px 12px;
            border-radius:12px;font-size:0.85em;
            font-weight:bold;
            display:inline-block;
            margin-bottom:12px;">
            🔴 CRITICAL 特集
        </span>
        <h1 style="font-size:1.4em;
            margin-bottom:8px;">
            {cve_id}<br>
            {product}
            {"(" + vendor + ")" if vendor else ""}
        </h1>
        <p>{description}</p>
        <div style="font-size:0.85em;
            opacity:0.8;margin-top:8px;">
            📅 CISA KEV追加日: {display_date}
            {"　⏰ 対応期限: " + due_date
             if due_date else ""}
        </div>
    </div>

    {ransomware_note}

    {"<div style='background:#FCEBEB;border:1px solid #cc0000;border-radius:8px;padding:16px;margin:16px 0;text-align:center;'><div>⏰ 対応期限</div><div style=font-size:1.4em;font-weight:bold;color:#cc0000;>" + due_date + "</div></div>" if due_date else ""}

    <div class="card">
        <h2>🏢 中小企業への影響</h2>
        <div style="background:#fff8e1;
            border-left:4px solid #ffaa00;
            padding:16px;border-radius:4px;">
            <p>{impact}</p>
        </div>
    </div>

    <div class="card">
        <h2>✅ 今すぐできる対策</h2>
        <ul style="list-style:none;padding:0;">
            {mitigation_html}
        </ul>
    </div>

    <div class="card">
        <h2>🔗 一次情報源・参考リンク</h2>
        <p>
            <a href="https://www.cisa.gov/
known-exploited-vulnerabilities-catalog"
               target="_blank">
                CISA KEV カタログ
            </a> /
            <a href="https://www.jpcert.or.jp/"
               target="_blank">JPCERT/CC</a> /
            <a href="https://jvndb.jvn.jp/"
               target="_blank">JVN iPedia</a>
        </p>
    </div>

    <div class="card">
        <h2>💬 対応に困ったら</h2>
        <p>
            自社システムへの影響確認や
            対応方法がわからない場合は
            専門家への相談をお勧めします。
        </p>
        <p style="margin-top:12px;">
            <a href="../index.html"
               style="background:#7A74B8;
               color:white;padding:10px 20px;
               border-radius:20px;
               text-decoration:none;">
                30分の無料相談はこちら
            </a>
        </p>
    </div>

    <footer>
        <p>
            <strong>畠山正彦</strong> |
            ITセキュリティコンサルタント
        </p>
        <p style="font-size:0.8em;color:#999;">
            本情報はCISA KEV等の公開情報を基に
            作成しています。実際の対応は各情報源
            および専門家への相談のうえ行ってください。
        </p>
    </footer>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# アーカイブHTML生成
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_week_html(
    week_date, kev_list, counts, all_history
):
    """週次レポートHTMLを生成"""
    try:
        display_date = datetime.strptime(
            week_date, "%Y-%m-%d"
        ).strftime("%Y年%m月%d日")
    except Exception:
        display_date = week_date

    # 90日以内のCRITICALを収集
    cutoff_90 = (
        datetime.now() - timedelta(days=90)
    ).strftime("%Y-%m-%d")

    persistent = [
        v for v in all_history.values()
        if (v.get("severity") == "CRITICAL" and
            v.get("dateAdded", "") >= cutoff_90 and
            v.get("type") == "kev")
    ]
    persistent = sorted(
        persistent,
        key=lambda x: x.get("dateAdded", ""),
        reverse=True
    )

    cards_html = ""
    for v in persistent:
        date_added = v.get("dateAdded", "")
        try:
            days_ago = (
                datetime.now() -
                datetime.strptime(
                    date_added, "%Y-%m-%d")
            ).days
            days_text = (
                f"追加 {days_ago}日前"
                if days_ago > 0 else "本日追加"
            )
        except Exception:
            days_text = ""

        safe_id = v["id"].replace(
            "/", "-").replace(":", "-").replace(
            " ", "-")
        feature_path = (
            f"feature/{safe_id}.html"
        )
        feature_link = ""
        if (v.get("is_major") and
                os.path.exists(
                    f"{DOCS_DIR}/{feature_path}")):
            feature_link = (
                f' <a href="{feature_path}"'
                f' style="background:#7A74B8;'
                f'color:white;padding:2px 8px;'
                f'border-radius:10px;'
                f'font-size:0.8em;'
                f'text-decoration:none;">'
                f'📋 特集記事</a>'
            )

        cards_html += f"""
        <div class="persistent-critical">
            <span class="badge badge-critical">
                🔴 CRITICAL
            </span>
            {feature_link}
            <strong>{v['id']}</strong> |
            {v.get('product', '')}
            ({v.get('vendor', '')})<br>
            <p>{v.get('description', '')}</p>
            <p>📅 追加日:{date_added}
               ⏰ 期限:{v.get('dueDate', '-')}</p>
            <div class="days-since">
                {days_text}
            </div>
            <a href="https://www.cisa.gov/
known-exploited-vulnerabilities-catalog"
               target="_blank">
                🔗 対策を確認する(CISA)
            </a>
        </div>"""

    if not cards_html:
        cards_html = (
            "<p>直近90日間のCRITICALはありません</p>"
        )

    total = sum(counts.values())

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>脆弱性情報 {display_date} |
    畠山正彦</title>
    <style>{get_css()}</style>
</head>
<body>
    <p>
        <a href="index.html">
            ← 最新レポートに戻る
        </a> |
        <a href="archive.html">
            📚 アーカイブ一覧
        </a>
    </p>
    <h1>🔍 脆弱性情報レポート</h1>
    <div class="update-time">
        📅 レポート日: {display_date}
    </div>

    <div class="summary-box">
        <h2>📊 重要度サマリー</h2>
        <table>
            <tr>
                <td>🔴 CRITICAL</td>
                <td><strong>
                    {counts['CRITICAL']}件
                </strong></td>
            </tr>
            <tr>
                <td>🟠 高</td>
                <td><strong>
                    {counts['高']}件
                </strong></td>
            </tr>
            <tr>
                <td>🟡 中</td>
                <td><strong>
                    {counts['中']}件
                </strong></td>
            </tr>
            <tr>
                <td>🟢 低</td>
                <td><strong>
                    {counts['低']}件
                </strong></td>
            </tr>
            <tr>
                <td><strong>合計</strong></td>
                <td><strong>{total}件</strong></td>
            </tr>
        </table>
    </div>

    <h2>🔴 CRITICAL:実際に悪用確認済み
    <small style="font-size:0.7em;
        color:#cc0000;">(直近90日間 常時掲載)</small>
    </h2>
    {cards_html}

    <div class="disclaimer">
        <h3>⚠️ 免責事項</h3>
        <p>本情報はCISA KEV・JPCERT/CC・
        JVN iPediaの公開情報を収集・整理したものです。
        実際の対応は各情報源および専門家への
        相談のうえ行ってください。</p>
    </div>

    <footer>
        <p>
            <strong>畠山正彦</strong> |
            ITセキュリティコンサルタント
        </p>
        <p style="font-size:0.8em;color:#999;">
            © 2026 畠山正彦 All Rights Reserved.
        </p>
    </footer>
</body>
</html>"""


def generate_archive_page(all_data, feature_vulns):
    """アーカイブ一覧ページを生成"""
    rows = ""
    for date in sorted(
        all_data.keys(), reverse=True
    ):
        d = all_data[date]
        s = d["summary"]
        try:
            display = datetime.strptime(
                date, "%Y-%m-%d"
            ).strftime("%Y年%m月%d日")
        except Exception:
            display = date
        rows += f"""
        <tr>
            <td><a href="{date}.html">
                {display}</a></td>
            <td style="color:#cc0000;">
                <strong>{s['critical']}</strong>
            </td>
            <td style="color:#ff6600;">
                {s['high']}</td>
            <td style="color:#ffaa00;">
                {s['medium']}</td>
            <td style="color:#009900;">
                {s['low']}</td>
            <td>{s['total']}</td>
        </tr>"""

    feature_rows = ""
    for vuln in feature_vulns:
        safe_id = vuln["id"].replace(
            "/", "-").replace(":", "-").replace(
            " ", "-")
        feature_rows += f"""
        <tr>
            <td>
                <a href="feature/{safe_id}.html">
                    📋 {vuln['id']}
                </a>
            </td>
            <td>{vuln.get('product', '')}</td>
            <td>{vuln.get('vendor', '')}</td>
            <td>{vuln.get('dateAdded', '')}</td>
        </tr>"""

    feature_section = ""
    if feature_rows:
        feature_section = f"""
        <h2>📋 特集ページ一覧</h2>
        <p>重大な脆弱性の詳細解説・対策情報です。</p>
        <table>
            <thead>
                <tr>
                    <th>脆弱性ID</th>
                    <th>製品</th>
                    <th>ベンダー</th>
                    <th>KEV追加日</th>
                </tr>
            </thead>
            <tbody>{feature_rows}</tbody>
        </table><br>"""

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>レポートアーカイブ | 畠山正彦</title>
    <style>{get_css()}</style>
</head>
<body>
    <h1>📚 脆弱性レポート アーカイブ</h1>
    <p><a href="index.html">
        ← 最新レポートに戻る
    </a></p>
    <p>累計 {len(all_data)}週分のデータ</p>

    {feature_section}

    <h2>📅 週次レポート一覧</h2>
    <table>
        <thead>
            <tr>
                <th>レポート日</th>
                <th>🔴CRITICAL</th>
                <th>🟠高</th>
                <th>🟡中</th>
                <th>🟢低</th>
                <th>合計</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>

    <footer>
        <p>
            <strong>畠山正彦</strong> |
            ITセキュリティコンサルタント
        </p>
        <p style="font-size:0.8em;color:#999;">
            © 2026 畠山正彦 All Rights Reserved.
        </p>
    </footer>
</body>
</html>"""

    with open(f"{DOCS_DIR}/archive.html",
              "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ archive.html 生成完了")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# メイン処理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()  # SSL警告を抑制

    print("📡 バックフィル開始")
    print(f"対象週: {BACKFILL_DATES}")

    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(FEATURE_DIR, exist_ok=True)

    # KEV全件取得(1回だけ)
    all_kev = fetch_all_kev()
    if not all_kev:
        print("❌ KEVデータが取得できませんでした")
        exit(1)

    # 既存データを読み込む
    json_path = f"{DOCS_DIR}/data.json"
    if os.path.exists(json_path):
        with open(json_path, "r",
                  encoding="utf-8") as f:
            all_data = json.load(f)
        print(f"既存週次データ: {len(all_data)}週分")
    else:
        all_data = {}

    hist_path = f"{DOCS_DIR}/vuln_history.json"
    if os.path.exists(hist_path):
        with open(hist_path, "r",
                  encoding="utf-8") as f:
            history = json.load(f)
        print(
            f"既存履歴: "
            f"{len(history.get('vulnerabilities', {}))}件"
        )
    else:
        history = {"vulnerabilities": {}}

    vulns_hist = history.setdefault(
        "vulnerabilities", {}
    )

    # 各週を処理
    for week_date in BACKFILL_DATES:
        print(f"\n{'='*50}")
        print(f"処理: {week_date}")

        week_kev = filter_kev_by_week(
            all_kev, week_date
        )
        print(f"該当KEV: {len(week_kev)}件")

        counts = {
            "CRITICAL": len(week_kev),
            "高": 0, "中": 0, "低": 0
        }

        # 履歴に追加
        new_cnt = 0
        for v in week_kev:
            cid = v["cveID"]
            if cid not in vulns_hist:
                vulns_hist[cid] = {
                    "id": cid,
                    "type": "kev",
                    "product": v["product"],
                    "vendor": v["vendorProject"],
                    "description": v[
                        "shortDescription"],
                    "dateAdded": v["dateAdded"],
                    "dueDate": v["dueDate"],
                    "severity": "CRITICAL",
                    "first_seen": week_date,
                    "is_major": is_major(v),
                    "feature_created": False,
                    "source_url": (
                        "https://www.cisa.gov/"
                        "known-exploited-"
                        "vulnerabilities-catalog"
                    )
                }
                new_cnt += 1

        print(f"履歴追加: {new_cnt}件")

        # data.jsonに追加
        if week_date not in all_data:
            all_data[week_date] = {
                "date": week_date,
                "summary": {
                    "critical": counts["CRITICAL"],
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": counts["CRITICAL"]
                },
                "kev": [
                    {
                        "cveID": v["cveID"],
                        "product": v["product"],
                        "vendorProject":
                            v["vendorProject"],
                        "description":
                            v["shortDescription"],
                        "dateAdded": v["dateAdded"],
                        "dueDate": v["dueDate"]
                    }
                    for v in week_kev
                ],
                "jpcert": [],
                "jvn": []
            }
            print(f"data.json: {week_date} 追加")
        else:
            print(f"data.json: {week_date} 既存スキップ")

        # 週次HTMLを生成
        html_path = f"{DOCS_DIR}/{week_date}.html"
        if not os.path.exists(html_path):
            html = build_week_html(
                week_date, week_kev,
                counts, vulns_hist
            )
            with open(html_path, "w",
                      encoding="utf-8") as f:
                f.write(html)
            print(f"✅ {week_date}.html 生成")
        else:
            print(f"✅ {week_date}.html 既存スキップ")

    # 特集ページを生成
    print(f"\n{'='*50}")
    print("📋 特集ページを生成中...")
    feature_vulns = []
    for cid, v in vulns_hist.items():
        if (v.get("severity") == "CRITICAL" and
                v.get("is_major", False)):
            safe_id = v["id"].replace(
                "/", "-").replace(":", "-"
            ).replace(" ", "-")
            fp = f"{FEATURE_DIR}/{safe_id}.html"
            if not os.path.exists(fp):
                generate_feature_page({
                    "cveID": v["id"],
                    "product": v.get("product", ""),
                    "vendorProject": v.get("vendor", ""),
                    "shortDescription": v.get(
                        "description", ""),
                    "dateAdded": v.get("dateAdded", ""),
                    "dueDate": v.get("dueDate", ""),
                })
                print(f"✅ 特集ページ: {v['id']}")
            v["feature_created"] = True
            feature_vulns.append(v)

    # data.jsonを保存
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_data, f,
                  ensure_ascii=False, indent=2)
    print(f"\n✅ data.json 保存 ({len(all_data)}週分)")

    # vuln_history.jsonを保存
    with open(hist_path, "w", encoding="utf-8") as f:
        json.dump(history, f,
                  ensure_ascii=False, indent=2)
    print(
        f"✅ vuln_history.json 保存 "
        f"({len(vulns_hist)}件)"
    )

    # archive.htmlを更新
    generate_archive_page(all_data, feature_vulns)

    print("\n=== バックフィル完了 ===")
    print(f"週次累計: {len(all_data)}週分")
    print(f"特集ページ: {len(feature_vulns)}件")
