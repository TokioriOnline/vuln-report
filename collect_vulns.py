import requests
import feedparser
import json
import os
from datetime import datetime, timedelta

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 設定
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL_DISPLAY_DAYS = 90   # トップページに残す日数
HISTORY_DAYS = 365           # 蓄積する日数(1年)
DOCS_DIR = "docs"
FEATURE_DIR = "docs/feature"

# 特集ページ対象となる主要製品キーワード
MAJOR_PRODUCTS = [
    "windows", "exchange", "apache", "cisco",
    "fortinet", "vmware", "citrix", "ivanti",
    "palo alto", "juniper", "f5", "sharepoint",
    "outlook", "office", "chrome", "firefox",
    "adobe", "log4j", "spring", "confluence",
    "gitlab", "github", "jenkins"
]

# 特集ページ対象となる脅威キーワード
MAJOR_THREATS = [
    "ransomware", "ランサムウェア",
    "remote code execution", "リモートコード実行",
    "zero-day", "ゼロデイ", "0-day",
    "nation-state", "国家支援",
    "apt", "supply chain", "サプライチェーン"
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 重要度分類
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def classify_severity(item, source):
    title = item.get("title", "").lower()
    summary = item.get("summary", "").lower()
    text = title + " " + summary

    if source == "kev":
        return {
            "level": "CRITICAL",
            "icon": "🔴",
            "reason": "実際の攻撃での悪用が確認済み"
        }

    high_keywords = [
        "リモートコード", "任意のコード", "rce",
        "認証バイパス", "特権昇格", "権限昇格",
        "ゼロデイ", "悪用", "緊急", "critical",
        "remote code execution"
    ]
    if any(k in text for k in high_keywords):
        return {
            "level": "高",
            "icon": "🟠",
            "reason": "リモートからの深刻な攻撃が可能"
        }

    medium_keywords = [
        "サービス妨害", "dos", "情報漏洩",
        "クロスサイト", "xss", "sql", "重要",
        "denial of service"
    ]
    if any(k in text for k in medium_keywords):
        return {
            "level": "中",
            "icon": "🟡",
            "reason": "悪用された場合に一定の被害が発生"
        }

    return {
        "level": "低",
        "icon": "🟢",
        "reason": "影響は限定的・モニタリング推奨"
    }


def is_major_vulnerability(vuln):
    """特集ページを作るべき重大脆弱性か判定"""
    text = (
        vuln.get("product", "") + " " +
        vuln.get("description", "") + " " +
        vuln.get("vendorProject", "")
    ).lower()

    has_major_product = any(
        p in text for p in MAJOR_PRODUCTS
    )
    has_major_threat = any(
        t in text for t in MAJOR_THREATS
    )
    return has_major_product or has_major_threat


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# データ収集
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fetch_cisa_kev(days=7):
    try:
        url = (
            "https://www.cisa.gov/sites/default/files"
            "/feeds/known_exploited_vulnerabilities.json"
        )
        data = requests.get(url, timeout=15).json()
        cutoff = datetime.now() - timedelta(days=days)
        return [
            v for v in data["vulnerabilities"]
            if datetime.strptime(
                v["dateAdded"], "%Y-%m-%d") > cutoff
        ]
    except Exception as e:
        print(f"CISA KEV取得エラー: {e}")
        return []


def fetch_cisa_kev_all():
    """KEV全件取得(蓄積用)"""
    try:
        url = (
            "https://www.cisa.gov/sites/default/files"
            "/feeds/known_exploited_vulnerabilities.json"
        )
        return requests.get(url, timeout=15).json()[
            "vulnerabilities"
        ]
    except Exception as e:
        print(f"CISA KEV全件取得エラー: {e}")
        return []


def fetch_jpcert():
    try:
        feed = feedparser.parse(
            "https://www.jpcert.or.jp/rss/jpcert.rdf"
        )
        return [
            {
                "title": e.get("title", ""),
                "link": e.get("link", ""),
                "summary": e.get("summary", ""),
                "published": e.get("published", "")
            }
            for e in feed.entries[:10]
        ]
    except Exception as e:
        print(f"JPCERT取得エラー: {e}")
        return []


def fetch_jvn():
    try:
        feed = feedparser.parse(
            "https://jvndb.jvn.jp/myjvn"
            "?method=getFeedInfo&feed=hnd"
        )
        return [
            {
                "title": e.get("title", ""),
                "link": e.get("link", ""),
                "summary": e.get("summary", ""),
                "published": e.get("published", "")
            }
            for e in feed.entries[:10]
        ]
    except Exception as e:
        print(f"JVN取得エラー: {e}")
        return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 脆弱性履歴の蓄積(1年分)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def load_vuln_history():
    """既存の脆弱性履歴を読み込む"""
    path = f"{DOCS_DIR}/vuln_history.json"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"vulnerabilities": {}, "last_updated": ""}


def save_vuln_history(history):
    """脆弱性履歴を保存"""
    path = f"{DOCS_DIR}/vuln_history.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            history, f,
            ensure_ascii=False, indent=2
        )
    print(
        f"✅ vuln_history.json 保存完了 "
        f"(累計 {len(history['vulnerabilities'])}件)"
    )


def update_vuln_history(kev_list, jpcert_list, jvn_list):
    """
    脆弱性履歴を更新
    ・新規エントリを追加(既存は上書きしない)
    ・1年以上前のエントリを削除
    ・特集ページ対象フラグを付与
    """
    history = load_vuln_history()
    vulns = history["vulnerabilities"]
    today = datetime.now().strftime("%Y-%m-%d")
    cutoff = (
        datetime.now() - timedelta(days=HISTORY_DAYS)
    ).strftime("%Y-%m-%d")

    new_count = 0

    # KEV脆弱性を追加
    for v in kev_list:
        cve_id = v["cveID"]
        if cve_id not in vulns:
            vulns[cve_id] = {
                "id": cve_id,
                "type": "kev",
                "product": v["product"],
                "vendor": v["vendorProject"],
                "description": v["shortDescription"],
                "dateAdded": v["dateAdded"],
                "dueDate": v["dueDate"],
                "severity": "CRITICAL",
                "first_seen": today,
                "is_major": is_major_vulnerability(v),
                "feature_created": False,
                "source_url": (
                    "https://www.cisa.gov/"
                    "known-exploited-vulnerabilities-catalog"
                )
            }
            new_count += 1
        else:
            # 特集対象フラグだけ更新
            if not vulns[cve_id].get("is_major"):
                vulns[cve_id]["is_major"] = \
                    is_major_vulnerability(v)

    # JPCERT/JVNを追加(タイトルをIDとして使用)
    for items, source in [
        (jpcert_list, "jpcert"),
        (jvn_list, "jvn")
    ]:
        for item in items:
            title = item.get("title", "")
            link = item.get("link", "")
            if not title:
                continue
            # リンクをキーとして使用
            key = link or title[:50]
            if key not in vulns:
                sev = classify_severity(item, source)
                vulns[key] = {
                    "id": key,
                    "type": source,
                    "title": title,
                    "link": link,
                    "summary": item.get(
                        "summary", "")[:200],
                    "published": item.get(
                        "published", today),
                    "dateAdded": today,
                    "severity": sev["level"],
                    "first_seen": today,
                    "is_major": False,
                    "feature_created": False,
                    "source_url": link
                }
                new_count += 1

    # 1年以上前のエントリを削除
    removed = [
        k for k, v in vulns.items()
        if v.get("dateAdded", today) < cutoff
    ]
    for k in removed:
        del vulns[k]

    history["vulnerabilities"] = vulns
    history["last_updated"] = today

    print(
        f"✅ 履歴更新: 新規{new_count}件追加 "
        f"/ {len(removed)}件削除(1年超) "
        f"/ 累計{len(vulns)}件"
    )

    save_vuln_history(history)
    return history


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 特集ページ生成
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_feature_page(vuln):
    """重大脆弱性の特集ページを生成"""
    os.makedirs(FEATURE_DIR, exist_ok=True)

    vuln_id = vuln["id"]
    safe_id = vuln_id.replace(
        "/", "-").replace(":", "-").replace(" ", "-")
    filepath = f"{FEATURE_DIR}/{safe_id}.html"

    # 既に作成済みの場合はスキップ
    if os.path.exists(filepath):
        return filepath

    product = vuln.get("product", "")
    vendor = vuln.get("vendor", "")
    description = vuln.get("description", "")
    date_added = vuln.get("dateAdded", "")
    due_date = vuln.get("dueDate", "")
    source_url = vuln.get("source_url", "")
    title = vuln.get("title", vuln_id)

    # 製品別の影響・対策コメント
    product_lower = product.lower()
    description_lower = description.lower()

    if "windows" in product_lower:
        impact = (
            "Windows製品の脆弱性は国内中小企業への"
            "影響が特に広範です。社内PCやサーバー、"
            "リモートデスクトップ環境が攻撃対象と"
            "なります。Windows Updateの自動更新が"
            "有効になっているか今すぐ確認してください。"
        )
        mitigation = [
            "Windows Updateを即時実行する",
            "自動更新が有効になっているか全端末を確認",
            "RDP(リモートデスクトップ)の不要な公開を停止",
            "EDRやウイルス対策ソフトの定義ファイルを更新"
        ]
    elif any(p in product_lower for p in
             ["cisco", "fortinet", "vpn", "gateway",
              "citrix", "ivanti"]):
        impact = (
            "VPN機器・ネットワーク機器の脆弱性は、"
            "リモートワーク環境が普及した現在において"
            "特に深刻です。外部から社内ネットワークへの"
            "侵入口となるため、攻撃者に悪用された場合、"
            "ネットワーク全体が危険にさらされます。"
        )
        mitigation = [
            "ベンダーが提供するファームウェアを即時更新",
            "管理画面へのアクセスをIPアドレスで制限",
            "不審な接続ログがないか確認",
            "MFA(多要素認証)を有効化"
        ]
    elif any(p in product_lower for p in
             ["apache", "iis", "nginx", "tomcat"]):
        impact = (
            "Webサーバーの脆弱性は、自社のWebサイトや"
            "社内システムへの不正アクセス・改ざんに"
            "つながります。外部委託しているWebサイトも"
            "対象となる可能性があります。"
        )
        mitigation = [
            "Webサーバーソフトウェアを最新版に更新",
            "外部委託先のベンダーに対応状況を確認",
            "Webアプリケーションファイアウォール(WAF)の導入を検討",
            "サーバーログに不審なアクセスがないか確認"
        ]
    elif any(p in product_lower for p in
             ["exchange", "outlook", "office", "365"]):
        impact = (
            "メール・グループウェアの脆弱性は、"
            "ビジネスメール詐欺(BEC)や情報漏洩の"
            "入口となります。クラウド版(Microsoft 365)を"
            "利用している場合も、オンプレミス版と"
            "あわせて確認が必要です。"
        )
        mitigation = [
            "Microsoft Updateを即時適用",
            "メールフィルタリングの設定を強化",
            "不審なメールの報告フローを社内で周知",
            "管理者アカウントのMFAを確認"
        ]
    else:
        impact = (
            "この脆弱性が自社のシステムで使用している"
            "ソフトウェアに該当しないか確認してください。"
            "該当する場合は、ベンダーが提供するパッチや"
            "アップデートを速やかに適用することが重要です。"
        )
        mitigation = [
            "影響を受けるソフトウェアのバージョンを確認",
            "ベンダーの公式情報でパッチの有無を確認",
            "パッチがない場合は回避策を適用",
            "ITベンダーや専門家に相談"
        ]

    # ランサムウェア関連の追記
    ransomware_note = ""
    if any(t in description_lower for t in
           ["ransomware", "ランサムウェア"]):
        ransomware_note = """
        <div class="ransomware-warn">
            <h3>⚠️ ランサムウェアによる悪用が報告されています</h3>
            <p>
                この脆弱性はランサムウェア攻撃グループによる
                悪用が確認されています。感染した場合、
                社内データが暗号化され、身代金を要求される
                被害が発生しています。<br>
                <strong>
                    バックアップがオフラインで保管されているか
                    今すぐ確認してください。
                </strong>
            </p>
        </div>"""

    mitigation_html = "".join(
        f"<li>{m}</li>" for m in mitigation
    )

    display_date = ""
    if date_added:
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
    <title>
        【特集】{vuln_id} {product} |
        Tokiori Online 脆弱性情報
    </title>
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/
@tabler/icons-webfont@3.34.0/tabler-icons.min.css">
    <style>
        body{{
            font-family:'Helvetica Neue',sans-serif;
            max-width:900px;margin:auto;
            padding:20px;background:#f5f5f5;
            color:#333;
        }}
        .back-link{{
            margin-bottom:20px;
            font-size:0.9em;
        }}
        .back-link a{{color:#7A74B8;
            text-decoration:none;}}
        .feature-header{{
            background:#1a1a2e;color:white;
            border-radius:8px;padding:24px;
            margin-bottom:20px;
        }}
        .feature-header h1{{
            font-size:1.4em;margin-bottom:8px;
        }}
        .critical-badge{{
            display:inline-block;
            background:#cc0000;color:white;
            padding:4px 12px;border-radius:12px;
            font-size:0.85em;font-weight:bold;
            margin-bottom:12px;
        }}
        .meta{{
            font-size:0.85em;opacity:0.8;
            margin-top:8px;
        }}
        .card{{
            background:white;border-radius:8px;
            padding:20px;margin:16px 0;
            border:0.5px solid #ddd;
        }}
        .card h2{{
            font-size:1.1em;color:#1a1a2e;
            margin-bottom:12px;
            border-left:4px solid #7A74B8;
            padding-left:10px;
        }}
        .impact-box{{
            background:#fff8e1;
            border-left:4px solid #ffaa00;
            padding:16px;border-radius:4px;
            margin:16px 0;
        }}
        .ransomware-warn{{
            background:#fff0f0;
            border-left:4px solid #cc0000;
            padding:16px;border-radius:4px;
            margin:16px 0;
        }}
        .ransomware-warn h3{{
            color:#cc0000;margin-bottom:8px;
        }}
        .mitigation-list{{
            list-style:none;padding:0;
        }}
        .mitigation-list li{{
            padding:10px 0;
            border-bottom:0.5px solid #eee;
            padding-left:28px;
            position:relative;
        }}
        .mitigation-list li:before{{
            content:"✓";
            position:absolute;left:0;
            color:#6A9A3A;font-weight:bold;
        }}
        .mitigation-list li:last-child{{
            border-bottom:none;
        }}
        .source-links a{{
            display:inline-block;
            margin:4px 8px 4px 0;
            color:#7A74B8;
            font-size:0.9em;
        }}
        .deadline-box{{
            background:#FCEBEB;
            border:1px solid #cc0000;
            border-radius:8px;
            padding:16px;margin:16px 0;
            text-align:center;
        }}
        .deadline-box .date{{
            font-size:1.4em;
            font-weight:bold;color:#cc0000;
        }}
        footer{{
            text-align:center;margin-top:40px;
            padding:20px;color:#666;
            font-size:0.85em;
            border-top:1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="back-link">
        <a href="../index.html">
            ← 最新レポートに戻る
        </a> |
        <a href="../archive.html">
            📚 アーカイブ一覧
        </a>
    </div>

    <div class="feature-header">
        <span class="critical-badge">
            🔴 CRITICAL 特集
        </span>
        <h1>
            {vuln_id}<br>
            {product}
            {"(" + vendor + ")" if vendor else ""}
        </h1>
        <p>{description}</p>
        <div class="meta">
            📅 CISA KEV追加日: {display_date}
            {"　⏰ 対応期限: " + due_date if due_date else ""}
        </div>
    </div>

    {ransomware_note}

    {f'''
    <div class="deadline-box">
        <div>⏰ 対応期限</div>
        <div class="date">{due_date}</div>
        <div style="font-size:0.85em;
            margin-top:4px;color:#666;">
            期限までにパッチ適用が必要です
        </div>
    </div>
    ''' if due_date else ""}

    <div class="card">
        <h2>
            <i class="ti ti-building"
               aria-hidden="true"></i>
            中小企業への影響
        </h2>
        <div class="impact-box">
            <p>{impact}</p>
        </div>
    </div>

    <div class="card">
        <h2>
            <i class="ti ti-shield-check"
               aria-hidden="true"></i>
            今すぐできる対策
        </h2>
        <ul class="mitigation-list">
            {mitigation_html}
        </ul>
    </div>

    <div class="card">
        <h2>
            <i class="ti ti-external-link"
               aria-hidden="true"></i>
            一次情報源・参考リンク
        </h2>
        <div class="source-links">
            <a href="https://www.cisa.gov/
known-exploited-vulnerabilities-catalog"
               target="_blank">
                🔗 CISA KEV カタログ
            </a>
            <a href="https://www.jpcert.or.jp/"
               target="_blank">
                🔗 JPCERT/CC
            </a>
            <a href="https://jvndb.jvn.jp/"
               target="_blank">
                🔗 JVN iPedia
            </a>
            {f'<a href="{source_url}" target="_blank">🔗 詳細情報</a>' if source_url else ""}
        </div>
        <p style="font-size:0.85em;
            color:#666;margin-top:12px;">
            最新の対応状況は必ず各一次情報源で
            ご確認ください。
        </p>
    </div>

    <div class="card">
        <h2>
            <i class="ti ti-help-circle"
               aria-hidden="true"></i>
            対応に困ったら
        </h2>
        <p>
            自社のシステムへの影響確認や対応方法が
            わからない場合は、専門家への相談を
            お勧めします。
        </p>
        <p style="margin-top:12px;">
            <a href="../index.html#contact"
               style="background:#7A74B8;
               color:white;padding:10px 20px;
               border-radius:20px;
               text-decoration:none;
               font-size:0.9em;">
                30分の無料相談はこちら
            </a>
        </p>
    </div>

    <footer>
        <p>
            <strong>畠山正彦</strong> |
            ITセキュリティコンサルタント<br>
            NIST / FISC / ISMS /
            自工会GL / 経産省SCS評価制度
        </p>
        <p style="font-size:0.8em;color:#999;
            margin-top:8px;">
            本情報はCISA KEV・JPCERT/CC等の
            公開情報を基に作成しています。
            実際の対応は各情報源および
            専門家への相談のうえ行ってください。
        </p>
    </footer>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ 特集ページ作成: {filepath}")
    return filepath


def generate_all_feature_pages(history):
    """
    特集ページ対象の脆弱性を全て処理
    ・is_major=True かつ CRITICAL のみ対象
    """
    vulns = history["vulnerabilities"]
    created = []

    for key, vuln in vulns.items():
        if (vuln.get("severity") == "CRITICAL" and
                vuln.get("is_major", False) and
                vuln.get("type") == "kev"):
            filepath = generate_feature_page(vuln)
            if filepath:
                created.append(
                    (key, vuln, filepath)
                )
                # 作成済みフラグを更新
                vulns[key]["feature_created"] = True

    print(f"✅ 特集ページ: {len(created)}件処理")
    return created


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CSS(共通)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_css():
    return """
        * { box-sizing: border-box; }
        body {
            font-family: 'Helvetica Neue',
                         sans-serif;
            max-width: 900px;
            margin: auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        h1 { color: #1a1a2e; }
        h2 {
            border-left: 4px solid #333;
            padding-left: 10px;
            margin-top: 30px;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 15px 20px;
            margin: 10px 0;
            box-shadow: 0 2px 4px
                        rgba(0,0,0,0.1);
        }
        .card.critical {
            border-left: 5px solid #cc0000;
        }
        .card.featured {
            border-left: 5px solid #7A74B8;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .badge-critical,
        .badge-CRITICAL {
            background: #cc0000;
            color: white;
        }
        .badge-高 {
            background: #ff6600;
            color: white;
        }
        .badge-中 {
            background: #ffaa00;
            color: white;
        }
        .badge-低 {
            background: #009900;
            color: white;
        }
        .badge-feature {
            background: #7A74B8;
            color: white;
            font-size: 0.75em;
            padding: 2px 8px;
            border-radius: 10px;
            margin-left: 8px;
        }
        .summary-box {
            background: #1a1a2e;
            color: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .summary-box h2 {
            color: white;
            border-color: white;
        }
        .summary-box table {
            width: 100%;
            border-collapse: collapse;
            background: transparent;
        }
        .summary-box td {
            padding: 8px;
            font-size: 1.05em;
            color: white;
        }
        .update-time {
            background: #e8f4f8;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        .persistent-critical {
            background: #fff0f0;
            border: 1px solid #ffcccc;
            border-radius: 8px;
            padding: 16px 20px;
            margin: 10px 0;
        }
        .days-since {
            font-size: 0.8em;
            color: #cc0000;
            margin-top: 4px;
        }
        .disclaimer {
            background: #fff8e1;
            border-left: 4px solid #ffaa00;
            padding: 15px 20px;
            margin: 30px 0;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .disclaimer h3 { margin-top: 0; }
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
        a { color: #0066cc; }
        a:hover { text-decoration: underline; }
    """


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTML生成
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_html_content(
    today, kev_list, jpcert_list, jvn_list,
    counts, history, is_archive=False
):
    display_date = datetime.strptime(
        today, "%Y-%m-%d"
    ).strftime("%Y年%m月%d日")

    back_link = (
        '<p><a href="index.html">← 最新レポートに戻る</a></p>'
    ) if is_archive else ""

    cutoff_90 = (
        datetime.now() - timedelta(days=90)
    ).strftime("%Y-%m-%d")

    persistent_vulns = sorted(
        [v for v in history["vulnerabilities"].values()
         if v.get("severity") == "CRITICAL"
         and v.get("dateAdded", "") >= cutoff_90
         and v.get("type") == "kev"],
        key=lambda x: x.get("dateAdded", ""),
        reverse=True
    )

    sidebar_cards = ""
    for v in persistent_vulns:
        date_added = v.get("dateAdded", "")
        try:
            days_ago = (
                datetime.now() -
                datetime.strptime(date_added, "%Y-%m-%d")
            ).days
            days_text = f"{days_ago}日前" if days_ago > 0 else "本日"
        except Exception:
            days_text = ""
        safe_id = v["id"].replace("/","-").replace(":","-").replace(" ","-")
        fp = f"{FEATURE_DIR}/{safe_id}.html"
        feature_link = ""
        if v.get("is_major") and os.path.exists(fp):
            feature_link = (
                f' <a href="feature/{safe_id}.html"'
                f' style="background:#7A74B8;color:white;padding:1px 6px;border-radius:8px;font-size:0.75em;text-decoration:none;">'
                f'📋</a>'
            )
        first_seen = v.get("first_seen", "")
        cve_anchor = v["id"]
        report_link = (
            f'<a href="{first_seen}.html#{cve_anchor}"'
            f' style="font-size:0.78em;color:#0066cc;">'
            f'📄 週次レポート</a>'
        ) if first_seen else ""
        sidebar_cards += f"""<div style="background:#fff0f0;border-left:3px solid #cc0000;padding:10px 12px;margin:8px 0;border-radius:4px;font-size:0.85em;">
<div><strong>{v["id"]}</strong>{feature_link}</div>
<div style="color:#555;font-size:0.9em;margin:3px 0;">{v.get("product","")}</div>
<div style="color:#cc0000;font-size:0.8em;">{days_text} | 期限:{v.get("dueDate","-")}</div>
<div style="margin-top:4px;">{report_link}</div>
</div>"""

    if not sidebar_cards:
        sidebar_cards = "<p style='font-size:0.85em;color:#666;'>直近90日のCRITICALなし</p>"

    kev_html = ""
    for v in kev_list[:10]:
        safe_id = v["cveID"].replace("/","-").replace(":","-").replace(" ","-")
        vuln_hist = history["vulnerabilities"].get(v["cveID"], {})
        feature_link = ""
        fp = f"{FEATURE_DIR}/{safe_id}.html"
        if vuln_hist.get("is_major") and os.path.exists(fp):
            feature_link = (
                f' <a href="feature/{safe_id}.html"'
                f' style="background:#7A74B8;color:white;padding:2px 8px;border-radius:10px;font-size:0.8em;text-decoration:none;">📋 特集記事</a>'
            )
        kev_html += f"""<div class="card critical" id="{v["cveID"]}">
<span class="badge badge-critical">🔴 CRITICAL</span>{feature_link}
<strong>{v["cveID"]}</strong> | {v["product"]} ({v["vendorProject"]})<br>
<p>{v["shortDescription"]}</p>
<p>📅 {v["dateAdded"]} ⏰ 期限:{v["dueDate"]}</p>
<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">🔗 対策を確認する(CISA)</a>
</div>"""
    if not kev_html:
        kev_html = "<p>今週の新規追加はありません</p>"

    jpcert_html = ""
    for item in jpcert_list[:5]:
        sev = classify_severity(item, "jpcert")
        jpcert_html += f"""<div class="card">
<span class="badge badge-{sev["level"]}">{sev["icon"]} {sev["level"]}</span>
<strong>{item["title"]}</strong><br>
<small>{item["published"]}</small>
<p><a href="{item["link"]}" target="_blank">🔗 詳細(JPCERT/CC)</a></p>
</div>"""
    if not jpcert_html:
        jpcert_html = "<p>取得できませんでした</p>"

    jvn_html = ""
    for item in jvn_list[:5]:
        sev = classify_severity(item, "jvn")
        jvn_html += f"""<div class="card">
<span class="badge badge-{sev["level"]}">{sev["icon"]} {sev["level"]}</span>
<strong>{item["title"]}</strong><br>
<small>{item["published"]}</small>
<p><a href="{item["link"]}" target="_blank">🔗 詳細(JVN iPedia)</a></p>
</div>"""
    if not jvn_html:
        jvn_html = "<p>取得できませんでした</p>"

    total = sum(counts.values())

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>脆弱性情報レポート {display_date} | 畠山正彦</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.34.0/tabler-icons.min.css">
<style>{get_css()}
.layout{{display:flex;gap:20px;align-items:flex-start;margin-top:8px;}}
.main-col{{flex:1;min-width:0;}}
.side-col{{width:240px;flex-shrink:0;}}
.side-box{{background:white;border-radius:8px;padding:14px 16px;position:sticky;top:10px;}}
.side-box h3{{font-size:0.9em;color:#cc0000;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #ffcccc;}}
@media(max-width:768px){{.layout{{flex-direction:column;}}.side-col{{width:100%;}}.side-box{{position:static;}}}}
</style>
</head>
<body>
{back_link}
<h1>🔍 脆弱性情報レポート</h1>
<div class="update-time">📅 {display_date} | 毎週月曜 自動更新 |
<a href="archive.html">📚 過去レポート一覧</a> |
<a href="privacy.html">プライバシーポリシー</a>
</div>
<div class="summary-box">
<h2>📊 今週の重要度サマリー</h2>
<table>
<tr><td>🔴 CRITICAL(即時対応・24時間以内)</td><td><strong>{counts["CRITICAL"]}件</strong></td></tr>
<tr><td>🟠 高(優先対応・72時間以内)</td><td><strong>{counts["高"]}件</strong></td></tr>
<tr><td>🟡 中(計画対応・1週間以内)</td><td><strong>{counts["中"]}件</strong></td></tr>
<tr><td>🟢 低(モニタリング・月次確認)</td><td><strong>{counts["低"]}件</strong></td></tr>
<tr><td><strong>合計</strong></td><td><strong>{total}件</strong></td></tr>
</table>
</div>
<div class="layout">
<div class="main-col">
<h2>🔴 この週のCRITICAL <small style="font-size:0.65em;color:#cc0000;">({counts["CRITICAL"]}件)</small></h2>
<p style="font-size:0.9em;color:#666;margin-bottom:12px;">この週にCISAが新たに「実際に悪用されている」と認定した脆弱性です。</p>
{kev_html}
<h2>🟠 JPCERT/CC:日本向け注意喚起</h2>
{jpcert_html}
<h2>🟡 JVN iPedia:国内製品脆弱性情報</h2>
{jvn_html}
<div class="disclaimer">
<h3>⚠️ 免責事項</h3>
<p>本情報はCISA KEV・JPCERT/CC・JVN iPediaの公開情報を収集・整理したものです。実際の対応は各情報源および専門家への相談のうえ行ってください。</p>
<p>一次情報源: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA KEV</a> / <a href="https://www.jpcert.or.jp/" target="_blank">JPCERT/CC</a> / <a href="https://jvndb.jvn.jp/" target="_blank">JVN iPedia</a></p>
</div>
</div>
<div class="side-col">
<div class="side-box">
<h3>🔴 過去のCRITICAL<span style="font-size:0.8em;color:#999;font-weight:normal;">(直近90日)</span></h3>
<p style="font-size:0.75em;color:#999;margin-bottom:6px;">📋 = 特集記事あり</p>
{sidebar_cards}
</div>
</div>
</div>
<footer>
<p><strong>畠山正彦</strong> | ITセキュリティコンサルタント<br>NIST / FISC / ISMS / 自工会GL / 経産省SCS評価制度</p>
<p><a href="https://www.linkedin.com/" target="_blank">LinkedIn</a> | <a href="https://note.com/" target="_blank">Note</a> | <a href="privacy.html">プライバシーポリシー</a></p>
<p style="font-size:0.8em;color:#999;">© 2026 畠山正彦 All Rights Reserved.</p>
</footer>
</body>
</html>"""

def generate_archive_index(all_data, feature_pages):
    rows = ""
    for date in sorted(
        all_data.keys(), reverse=True
    ):
        d = all_data[date]
        s = d["summary"]
        display = datetime.strptime(
            date, "%Y-%m-%d"
        ).strftime("%Y年%m月%d日")

        rows += f"""
        <tr>
            <td>
                <a href="{date}.html">
                    {display}
                </a>
            </td>
            <td style="color:#cc0000;">
                <strong>{s['critical']}</strong>
            </td>
            <td style="color:#ff6600;">
                {s['high']}
            </td>
            <td style="color:#ffaa00;">
                {s['medium']}
            </td>
            <td style="color:#009900;">
                {s['low']}
            </td>
            <td>{s['total']}</td>
        </tr>"""

    # 特集ページ一覧
    feature_section = ""  # 特集一覧はサイドバーに移動

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>レポートアーカイブ | 畠山正彦</title>
    <style>{get_css()}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px
                        rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #eee;
            text-align: center;
        }}
        th {{
            background: #1a1a2e;
            color: white;
        }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>📚 脆弱性レポート アーカイブ</h1>
    <p>
        <a href="index.html">
            ← 最新レポートに戻る
        </a>
    </p>
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
            ITセキュリティコンサルタント<br>
            <a href="privacy.html">
                プライバシーポリシー
            </a>
        </p>
        <p style="font-size:0.8em;color:#999;">
            © 2026 畠山正彦
            All Rights Reserved.
        </p>
    </footer>
</body>
</html>"""

    with open(f"{DOCS_DIR}/archive.html",
              "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ archive.html 生成完了")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JSONで週次データを蓄積
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def save_to_json(today, kev_list,
                 jpcert_list, jvn_list, counts):
    json_path = f"{DOCS_DIR}/data.json"

    if os.path.exists(json_path):
        with open(json_path, "r",
                  encoding="utf-8") as f:
            all_data = json.load(f)
    else:
        all_data = {}

    all_data[today] = {
        "date": today,
        "summary": {
            "critical": counts["CRITICAL"],
            "high": counts["高"],
            "medium": counts["中"],
            "low": counts["低"],
            "total": sum(counts.values())
        },
        "kev": [
            {
                "cveID": v["cveID"],
                "product": v["product"],
                "vendorProject": v["vendorProject"],
                "description": v["shortDescription"],
                "dateAdded": v["dateAdded"],
                "dueDate": v["dueDate"]
            }
            for v in kev_list
        ],
        "jpcert": [
            {
                "title": v["title"],
                "link": v["link"],
                "published": v["published"],
                "severity": classify_severity(
                    v, "jpcert")["level"]
            }
            for v in jpcert_list
        ],
        "jvn": [
            {
                "title": v["title"],
                "link": v["link"],
                "published": v["published"],
                "severity": classify_severity(
                    v, "jvn")["level"]
            }
            for v in jvn_list
        ]
    }

    with open(json_path, "w",
              encoding="utf-8") as f:
        json.dump(all_data, f,
                  ensure_ascii=False, indent=2)

    print(
        f"✅ data.json に {today} を追加 "
        f"(累計 {len(all_data)}週分)"
    )
    return all_data


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# プライバシーポリシー
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_privacy_policy():
    path = f"{DOCS_DIR}/privacy.html"
    if os.path.exists(path):
        print("✅ privacy.html 既存のためスキップ")
        return

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>プライバシーポリシー | 畠山正彦</title>
    <style>{get_css()}</style>
</head>
<body>
    <p><a href="index.html">← トップに戻る</a></p>
    <h1>プライバシーポリシー</h1>
    <p>最終更新日: 2026年7月</p>

    <h2>広告の配信について</h2>
    <p>
        本サイトはGoogle AdSenseを利用しています。
        Googleはユーザーのブラウザに保存される
        Cookieを使用して広告を配信します。
    </p>

    <h2>アクセス解析について</h2>
    <p>
        本サイトはGoogle Analytics等の
        アクセス解析ツールを使用する場合があります。
        収集されるデータは匿名であり、
        個人を特定するものではありません。
    </p>

    <h2>免責事項</h2>
    <p>
        本サイトに掲載する脆弱性情報は
        正確性を期しておりますが、
        内容の完全性・正確性を保証するものでは
        ありません。本サイトの情報利用により
        生じたいかなる損害についても
        責任を負いかねます。
    </p>

    <footer>
        <p>© 2026 畠山正彦 All Rights Reserved.</p>
    </footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ privacy.html 生成完了")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# メイン処理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    print("📡 情報収集開始...")
    today = datetime.now().strftime("%Y-%m-%d")

    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(FEATURE_DIR, exist_ok=True)

    # データ収集
    kev = fetch_cisa_kev(days=7)
    jpcert = fetch_jpcert()
    jvn = fetch_jvn()
    print(
        f"収集完了: KEV={len(kev)}件 "
        f"JPCERT={len(jpcert)}件 "
        f"JVN={len(jvn)}件"
    )

    # 重要度カウント(今週分)
    counts = {
        "CRITICAL": 0, "高": 0,
        "中": 0, "低": 0
    }
    for v in kev:
        counts["CRITICAL"] += 1
    for item in jpcert:
        level = classify_severity(
            item, "jpcert")["level"]
        counts[level] += 1
    for item in jvn:
        level = classify_severity(
            item, "jvn")["level"]
        counts[level] += 1

    # 脆弱性履歴を更新(1年分蓄積)
    history = update_vuln_history(
        kev, jpcert, jvn
    )

    # 特集ページを生成
    feature_pages = generate_all_feature_pages(
        history
    )

    # 履歴を保存(feature_createdフラグ更新後)
    save_vuln_history(history)

    # 週次データをdata.jsonに追加
    all_data = save_to_json(
        today, kev, jpcert, jvn, counts
    )

    # index.html(最新版)を生成
    html = build_html_content(
        today, kev, jpcert, jvn, counts,
        history, is_archive=False
    )
    with open(f"{DOCS_DIR}/index.html",
              "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ index.html 生成完了")

    # 日付付きアーカイブHTMLを生成
    archive_html = build_html_content(
        today, kev, jpcert, jvn, counts,
        history, is_archive=True
    )
    with open(f"{DOCS_DIR}/{today}.html",
              "w", encoding="utf-8") as f:
        f.write(archive_html)
    print(f"✅ {today}.html 保存完了")

    # アーカイブ一覧を生成
    generate_archive_index(all_data, feature_pages)

    # プライバシーポリシーを生成
    generate_privacy_policy()

    print("\n=== 完了 ===")
    print(f"週次累計: {len(all_data)}週分")
    print(
        f"脆弱性履歴: "
        f"{len(history['vulnerabilities'])}件"
    )
    print(
        f"特集ページ: {len(feature_pages)}件"
    )
    print(
        f"重要度: "
        f"CRITICAL={counts['CRITICAL']} "
        f"高={counts['高']} "
        f"中={counts['中']} "
        f"低={counts['低']}"
    )


main()
