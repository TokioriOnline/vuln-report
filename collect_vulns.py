import requests
import feedparser
from datetime import datetime, timedelta
import os

def classify_severity(item, source):
    title = item.get("title", "").lower()
    summary = item.get("summary", "").lower()
    text = title + summary

    if source == "kev":
        return {"level": "CRITICAL", "icon": "🔴",
                "reason": "実際の攻撃での悪用が確認済み"}

    high_keywords = [
        "リモートコード", "任意のコード", "rce",
        "認証バイパス", "特権昇格", "権限昇格",
        "ゼロデイ", "悪用", "緊急", "critical"
    ]
    if any(k in text for k in high_keywords):
        return {"level": "高", "icon": "🟠",
                "reason": "リモートからの深刻な攻撃が可能"}

    medium_keywords = [
        "サービス妨害", "dos", "情報漏洩",
        "クロスサイト", "xss", "sql", "重要"
    ]
    if any(k in text for k in medium_keywords):
        return {"level": "中", "icon": "🟡",
                "reason": "悪用された場合に一定の被害が発生"}

    return {"level": "低", "icon": "🟢",
            "reason": "影響は限定的・モニタリング推奨"}

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

def generate_html(kev_list, jpcert_list, jvn_list):
    now = datetime.now().strftime("%Y年%m月%d日 %H:%M")
    counts = {"CRITICAL": 0, "高": 0, "中": 0, "低": 0}

    # KEVのHTML生成
    kev_html = ""
    for v in kev_list[:10]:
        sev = classify_severity(v, "kev")
        counts[sev["level"]] += 1
        kev_html += f"""
        <div class="card critical">
            <span class="badge badge-critical">
                {sev['icon']} CRITICAL
            </span>
            <strong>{v['cveID']}</strong> |
            {v['product']} ({v['vendorProject']})<br>
            <p>{v['shortDescription']}</p>
            <p>📅 追加日:{v['dateAdded']}
               ⏰ 対応期限:{v['dueDate']}</p>
            <a href="https://www.cisa.gov/known-exploited
-vulnerabilities-catalog" target="_blank">
                🔗 対策を確認する(CISA)
            </a>
        </div>"""

    if not kev_html:
        kev_html = (
            "<p>直近7日間の新規追加はありません</p>"
        )

    # JPCERTのHTML生成
    jpcert_html = ""
    for item in jpcert_list[:5]:
        sev = classify_severity(item, "jpcert")
        counts[sev["level"]] += 1
        jpcert_html += f"""
        <div class="card">
            <span class="badge badge-{
                sev['level'].lower()
            }">
                {sev['icon']} {sev['level']}
            </span>
            <strong>{item['title']}</strong><br>
            <small>{item['published']}</small>
            <p><a href="{item['link']}"
                  target="_blank">
                🔗 対策・詳細を確認する(JPCERT/CC)
            </a></p>
        </div>"""

    # JVNのHTML生成
    jvn_html = ""
    for item in jvn_list[:5]:
        sev = classify_severity(item, "jvn")
        counts[sev["level"]] += 1
        jvn_html += f"""
        <div class="card">
            <span class="badge badge-{
                sev['level'].lower()
            }">
                {sev['icon']} {sev['level']}
            </span>
            <strong>{item['title']}</strong><br>
            <small>{item['published']}</small>
            <p><a href="{item['link']}"
                  target="_blank">
                🔗 対策・詳細を確認する(JVN iPedia)
            </a></p>
        </div>"""

    total = sum(counts.values())

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>脆弱性情報レポート | 畠山正彦</title>
    <style>
        body {{
            font-family: 'Helvetica Neue',
                         sans-serif;
            max-width: 900px;
            margin: auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        h1 {{ color: #1a1a2e; }}
        h2 {{ border-left: 4px solid #333;
              padding-left: 10px; }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 15px 20px;
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card.critical {{
            border-left: 5px solid #cc0000;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .badge-critical {{
            background: #cc0000;
            color: white;
        }}
        .badge-高 {{
            background: #ff6600;
            color: white;
        }}
        .badge-中 {{
            background: #ffaa00;
            color: white;
        }}
        .badge-低 {{
            background: #009900;
            color: white;
        }}
        .summary {{
            background: #1a1a2e;
            color: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .summary table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .summary td {{
            padding: 8px;
            font-size: 1.1em;
        }}
        a {{ color: #0066cc; }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        .update-time {{
            background: #e8f4f8;
            padding: 10px 15px;
            border-radius: 5px;
            font-size: 0.9em;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>

<h1>🔍 脆弱性情報レポート</h1>
<div class="update-time">
    🕐 最終更新: {now} |
    毎週月曜日 午前7時に自動更新
</div>

<div class="summary">
    <h2 style="color:white; border-color:white;">
        📊 今週のサマリー
    </h2>
    <table>
        <tr>
            <td>🔴 CRITICAL(即時対応・24時間以内)</td>
            <td><strong>{counts['CRITICAL']}件</strong>
            </td>
        </tr>
        <tr>
            <td>🟠 高(優先対応・72時間以内)</td>
            <td><strong>{counts['高']}件</strong></td>
        </tr>
        <tr>
            <td>🟡 中(計画対応・1週間以内)</td>
            <td><strong>{counts['中']}件</strong></td>
        </tr>
        <tr>
            <td>🟢 低(モニタリング・月次確認)</td>
            <td><strong>{counts['低']}件</strong></td>
        </tr>
        <tr>
            <td><strong>合計</strong></td>
            <td><strong>{total}件</strong></td>
        </tr>
    </table>
</div>

<h2>🔴 CISA KEV:実際に悪用確認済みの脆弱性</h2>
<p>米国CISAが「実際に攻撃者に悪用されている」と
認定した脆弱性です。最優先で対応してください。</p>
{kev_html}

<h2>🟠 JPCERT/CC:日本向け注意喚起</h2>
<p>JPCERT/CCが日本の組織向けに発信した
注意喚起情報です。</p>
{jpcert_html}

<h2>🟡 JVN iPedia:国内製品脆弱性情報</h2>
<p>IPAとJPCERT/CCが公開する国内製品・
日本語での脆弱性情報です。</p>
{jvn_html}

<footer>
    <p>
        <strong>畠山正彦</strong> |
        ITセキュリティコンサルタント<br>
        NIST / FISC / ISMS / 自工会GL /
        経産省SCS評価制度<br>
        お問い合わせ・ご相談:
        <a href="https://www.linkedin.com/in/"
           target="_blank">LinkedIn</a>
    </p>
    <p style="font-size:0.8em; color:#999;">
        本情報はCISA KEV・JPCERT/CC・JVN iPediaの
        公開情報を収集・整理したものです。<br>
        実際の対応は各情報源および
        専門家への相談をお勧めします。
    </p>
</footer>

</body>
</html>"""

    os.makedirs("docs", exist_ok=True)
    with open("docs/index.html", "w",
              encoding="utf-8") as f:
        f.write(html)
    print(f"✅ docs/index.html 生成完了 ({now})")

# 実行
print("📡 情報収集開始...")
kev = fetch_cisa_kev(days=7)
jpcert = fetch_jpcert()
jvn = fetch_jvn()
print(
    f"収集完了: KEV={len(kev)}件 "
    f"JPCERT={len(jpcert)}件 "
    f"JVN={len(jvn)}件"
)
generate_html(kev, jpcert, jvn)
