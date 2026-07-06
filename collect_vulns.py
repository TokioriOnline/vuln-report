import requests
import feedparser
import json
import os
from datetime import datetime, timedelta

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 重要度分類
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def classify_severity(item, source):
    title = item.get("title", "").lower()
    summary = item.get("summary", "").lower()
    text = title + summary

    if source == "kev":
        return {
            "level": "CRITICAL",
            "icon": "🔴",
            "reason": "実際の攻撃での悪用が確認済み"
        }

    high_keywords = [
        "リモートコード", "任意のコード", "rce",
        "認証バイパス", "特権昇格", "権限昇格",
        "ゼロデイ", "悪用", "緊急", "critical"
    ]
    if any(k in text for k in high_keywords):
        return {
            "level": "高",
            "icon": "🟠",
            "reason": "リモートからの深刻な攻撃が可能"
        }

    medium_keywords = [
        "サービス妨害", "dos", "情報漏洩",
        "クロスサイト", "xss", "sql", "重要"
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
# 方法B:JSONで累積保存
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def save_to_json(today, kev_list,
                 jpcert_list, jvn_list, counts):
    json_path = "docs/data.json"

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
        }
        .summary-box td {
            padding: 8px;
            font-size: 1.05em;
        }
        .update-time {
            background: #e8f4f8;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        .disclaimer {
            background: #fff8e1;
            border-left: 4px solid #ffaa00;
            padding: 15px 20px;
            margin: 30px 0;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .disclaimer h3 {
            margin-top: 0;
        }
        .ad-area {
            text-align: center;
            margin: 20px 0;
            min-height: 90px;
            background: #f9f9f9;
            border: 1px dashed #ccc;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #999;
            font-size: 0.85em;
        }
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
# HTML生成(共通部品)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_html_content(today, kev_list,
                       jpcert_list, jvn_list,
                       counts, is_archive=False):

    display_date = datetime.strptime(
        today, "%Y-%m-%d"
    ).strftime("%Y年%m月%d日")

    back_link = (
        '<p style="margin-bottom:20px;">'
        '<a href="index.html">← 最新レポートに戻る'
        '</a></p>'
    ) if is_archive else ""

    # ── AdSense ──────────────────────────
    # AdSense審査通過後に以下のコメントを外して
    # ca-pub-XXXX と data-ad-slot を実際の値に変更
    # ─────────────────────────────────────
    adsense_head = """
    <!-- Google AdSense(審査通過後に有効化) -->

    <script async
        src="https://pagead2.googlesyndication.com
/pagead/js/adsbygoogle.js?client=ca-pub-1682715102138016"
        crossorigin="anonymous">
    </script>

"""

    adsense_unit = """
    <!-- 広告ユニット(審査通過後に有効化) -->

    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="ca-pub-1682715102138016"
         data-ad-slot="2045988064"
         data-ad-format="auto"
         data-full-width-responsive="true">
    </ins>
    <script>
        (adsbygoogle = window.adsbygoogle
            || []).push({});
    </script>

    <div class="ad-area">広告エリア</div>
"""

    # ── KEV HTML ─────────────────────────
    kev_html = ""
    for v in kev_list[:10]:
        sev = classify_severity(v, "kev")
        kev_html += f"""
        <div class="card critical">
            <span class="badge badge-critical">
                {sev['icon']} CRITICAL
            </span>
            <strong>{v['cveID']}</strong> |
            {v['product']}
            ({v['vendorProject']})<br>
            <p>{v['shortDescription']}</p>
            <p>
                📅 追加日:{v['dateAdded']}
                &nbsp;
                ⏰ 対応期限:{v['dueDate']}
            </p>
            <a href="https://www.cisa.gov/
known-exploited-vulnerabilities-catalog"
               target="_blank">
                🔗 対策を確認する(CISA)
            </a>
        </div>"""

    if not kev_html:
        kev_html = "<p>直近7日間の新規追加はありません</p>"

    # ── JPCERT HTML ──────────────────────
    jpcert_html = ""
    for item in jpcert_list[:5]:
        sev = classify_severity(item, "jpcert")
        jpcert_html += f"""
        <div class="card">
            <span class="badge
                badge-{sev['level']}">
                {sev['icon']} {sev['level']}
            </span>
            <strong>{item['title']}</strong><br>
            <small>{item['published']}</small>
            <p>
                <a href="{item['link']}"
                   target="_blank">
                    🔗 対策・詳細を確認する
                    (JPCERT/CC)
                </a>
            </p>
        </div>"""

    if not jpcert_html:
        jpcert_html = "<p>取得できませんでした</p>"

    # ── JVN HTML ─────────────────────────
    jvn_html = ""
    for item in jvn_list[:5]:
        sev = classify_severity(item, "jvn")
        jvn_html += f"""
        <div class="card">
            <span class="badge
                badge-{sev['level']}">
                {sev['icon']} {sev['level']}
            </span>
            <strong>{item['title']}</strong><br>
            <small>{item['published']}</small>
            <p>
                <a href="{item['link']}"
                   target="_blank">
                    🔗 対策・詳細を確認する
                    (JVN iPedia)
                </a>
            </p>
        </div>"""

    if not jvn_html:
        jvn_html = "<p>取得できませんでした</p>"

    total = sum(counts.values())

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>脆弱性情報レポート {display_date}
           | Tokiori Online</title>
    {adsense_head}
    <style>{get_css()}</style>
</head>
<body>

{back_link}

<h1>🔍 脆弱性情報レポート</h1>

<div class="update-time">
    📅 レポート日: {display_date} |
    毎週月曜日 午前7時に自動更新 |
    <a href="archive.html">
        📚 過去のレポート一覧
    </a> |
    <a href="privacy.html">
        プライバシーポリシー
    </a>
</div>

<!-- 広告(上部) -->
{adsense_unit}

<div class="summary-box">
    <h2>📊 今週の重要度サマリー</h2>
    <table>
        <tr>
            <td>
                🔴 CRITICAL
                (即時対応・24時間以内)
            </td>
            <td>
                <strong>
                    {counts['CRITICAL']}件
                </strong>
            </td>
        </tr>
        <tr>
            <td>🟠 高(優先対応・72時間以内)</td>
            <td>
                <strong>{counts['高']}件</strong>
            </td>
        </tr>
        <tr>
            <td>🟡 中(計画対応・1週間以内)</td>
            <td>
                <strong>{counts['中']}件</strong>
            </td>
        </tr>
        <tr>
            <td>🟢 低(モニタリング・月次確認)</td>
            <td>
                <strong>{counts['低']}件</strong>
            </td>
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
日本語の脆弱性情報です。</p>
{jvn_html}

<!-- 広告(中間) -->
{adsense_unit}

<!-- 免責事項 -->
<div class="disclaimer">
    <h3>⚠️ 免責事項・ご利用にあたって</h3>
    <p>
        本サイトに掲載している脆弱性情報は、
        CISA KEV・JPCERT/CC・JVN iPediaが
        公開する情報を収集・整理したものです。
    </p>
    <ul>
        <li>
            本情報は参考情報であり、
            実際のセキュリティ対応を
            保証するものではありません
        </li>
        <li>
            掲載情報に基づく対応・判断は、
            必ず各情報源の原文および
            専門家への相談のうえ
            自己責任で行ってください
        </li>
        <li>
            本サイトの情報利用により
            生じた損害について、
            当サイトは一切の責任を
            負いかねます
        </li>
        <li>
            情報は自動収集のため、
            最新の状況と異なる場合があります。
            必ず一次情報源をご確認ください
        </li>
    </ul>
    <p>
        一次情報源:
        <a href="https://www.cisa.gov/
known-exploited-vulnerabilities-catalog"
           target="_blank">CISA KEV</a> /
        <a href="https://www.jpcert.or.jp/"
           target="_blank">JPCERT/CC</a> /
        <a href="https://jvndb.jvn.jp/"
           target="_blank">JVN iPedia</a>
    </p>
</div>

<footer>
    <p>
        <strong>Tokiori Online</strong><br>
        ITセキュリティコンサルタント Hatakeyama<br>
        NIST / FISC / ISMS /
        自工会GL / 経産省SCS評価制度
    </p>
    <p>
        <a href="https://www.linkedin.com/"
           target="_blank">LinkedIn</a> |
        <a href="https://note.com/"
           target="_blank">Note</a> |
        <a href="privacy.html">
            プライバシーポリシー
        </a>
    </p>
    <p style="font-size:0.8em; color:#999;">
        © 2026 Tokiori Online All Rights Reserved.
    </p>
</footer>

</body>
</html>"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 方法A:アーカイブ一覧ページ
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_archive_index(all_data):
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

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>レポートアーカイブ | Tokiori Online</title>
    <style>{get_css()}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px
                        rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            border: 1px solid #eee;
            text-align: center;
        }}
        th {{
            background: #1a1a2e;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
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
    <br>
    <footer>
        <p>
            <strong>Tokiori Online</strong> |
            ITセキュリティコンサルタント Hatakeyama<br>
            <a href="privacy.html">
                プライバシーポリシー
            </a>
        </p>
        <p style="font-size:0.8em;color:#999;">
            © 2026 Tokiori Online
            All Rights Reserved.
        </p>
    </footer>
</body>
</html>"""

    with open("docs/archive.html", "w",
              encoding="utf-8") as f:
        f.write(html)
    print("✅ archive.html 生成完了")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# プライバシーポリシーページ
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_privacy_policy():
    # 既に存在する場合はスキップ
    if os.path.exists("docs/privacy.html"):
        print("✅ privacy.html 既存のためスキップ")
        return

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width,
                   initial-scale=1.0">
    <title>プライバシーポリシー | Tokiori Online</title>
    <style>{get_css()}</style>
</head>
<body>
    <p>
        <a href="index.html">
            ← トップに戻る
        </a>
    </p>
    <h1>プライバシーポリシー</h1>
    <p>最終更新日:2026年7月</p>

    <h2>広告の配信について</h2>
    <p>
        本サイトはGoogle AdSenseを
        利用しています(予定)。
        Googleはユーザーのブラウザに
        保存されるCookieを使用して
        広告を配信します。
        Google広告のCookieを使用することにより、
        ユーザーがそのサイトや他のサイトに
        アクセスした際の情報に基づいて
        広告を配信することができます。
        Googleによる広告のCookieの使用は、
        <a href="https://policies.google.com/
technologies/ads"
           target="_blank">
            Googleの広告に関するポリシー
        </a>
        に従っています。
    </p>

    <h2>アクセス解析について</h2>
    <p>
        本サイトはGoogle Analytics等の
        アクセス解析ツールを使用する
        場合があります。収集されるデータは
        匿名であり、個人を特定するものでは
        ありません。
    </p>

    <h2>免責事項</h2>
    <p>
        本サイトに掲載する脆弱性情報は
        正確性を期しておりますが、
        内容の完全性・正確性を保証するものでは
        ありません。本サイトの情報利用により
        生じたいかなる損害についても
        責任を負いかねます。
        対応については必ず一次情報源および
        専門家にご確認ください。
    </p>

    <h2>お問い合わせ</h2>
    <p>
        本ポリシーに関するお問い合わせは
        LinkedInのメッセージ機能より
        お寄せください。
    </p>

    <footer>
        <p>
            © 2026 Tokiori Online 
            All Rights Reserved.
        </p>
    </footer>
</body>
</html>"""

    with open("docs/privacy.html", "w",
              encoding="utf-8") as f:
        f.write(html)
    print("✅ privacy.html 生成完了")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# メイン処理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    print("📡 情報収集開始...")
    today = datetime.now().strftime("%Y-%m-%d")

    # データ収集
    kev = fetch_cisa_kev(days=7)
    jpcert = fetch_jpcert()
    jvn = fetch_jvn()
    print(
        f"収集完了: KEV={len(kev)}件 "
        f"JPCERT={len(jpcert)}件 "
        f"JVN={len(jvn)}件"
    )

    # 重要度カウント
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

    os.makedirs("docs", exist_ok=True)

    # 方法B:JSONに累積保存
    all_data = save_to_json(
        today, kev, jpcert, jvn, counts
    )

    # 最新版index.htmlを生成
    html = build_html_content(
        today, kev, jpcert, jvn, counts,
        is_archive=False
    )
    with open("docs/index.html", "w",
              encoding="utf-8") as f:
        f.write(html)
    print("✅ index.html 生成完了")

    # 方法A:日付付きアーカイブHTMLを生成
    archive_html = build_html_content(
        today, kev, jpcert, jvn, counts,
        is_archive=True
    )
    archive_path = f"docs/{today}.html"
    with open(archive_path, "w",
              encoding="utf-8") as f:
        f.write(archive_html)
    print(f"✅ {archive_path} 保存完了")

    # アーカイブ一覧ページを更新
    generate_archive_index(all_data)

    # プライバシーポリシーを生成
    generate_privacy_policy()

    print("\n=== 完了 ===")
    print(f"累計データ: {len(all_data)}週分")
    print(
        f"重要度: "
        f"CRITICAL={counts['CRITICAL']} "
        f"高={counts['高']} "
        f"中={counts['中']} "
        f"低={counts['低']}"
    )


main()
