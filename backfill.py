"""
backfill.py
7月初めからの過去データを遡及生成するスクリプト
GitHub Actionsではなくローカルで一度だけ実行する
"""

import requests
import json
import os
import sys
from datetime import datetime, timedelta

# collect_vulns.py と同じディレクトリに置いて実行
# collect_vulns.py の関数をインポート
sys.path.insert(0, os.path.dirname(__file__))
from collect_vulns import (
    classify_severity,
    is_major_vulnerability,
    generate_feature_page,
    save_vuln_history,
    load_vuln_history,
    generate_archive_index,
    generate_privacy_policy,
    build_html_content,
    get_css,
    DOCS_DIR,
    FEATURE_DIR,
    CRITICAL_DISPLAY_DAYS,
    HISTORY_DAYS,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# バックフィル対象週の設定
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 7月初めから今週までの月曜日リスト
BACKFILL_DATES = [
    "2026-07-06",
    "2026-07-13",
    "2026-07-20",
]


def fetch_kev_for_week(week_start: str) -> list:
    """
    指定週(7日間)のCISA KEVエントリを取得
    week_start: YYYY-MM-DD形式の月曜日
    """
    try:
        url = (
            "https://www.cisa.gov/sites/default/files"
            "/feeds/known_exploited_vulnerabilities.json"
        )
        data = requests.get(url, timeout=15).json()
        all_vulns = data["vulnerabilities"]

        start = datetime.strptime(week_start, "%Y-%m-%d")
        end = start + timedelta(days=7)

        week_vulns = [
            v for v in all_vulns
            if start <= datetime.strptime(
                v["dateAdded"], "%Y-%m-%d") < end
        ]
        return week_vulns

    except Exception as e:
        print(f"KEV取得エラー: {e}")
        return []


def backfill_week(week_date: str, history: dict,
                  all_data: dict) -> tuple:
    """1週分のデータを遡及生成"""
    print(f"\n{'='*50}")
    print(f"処理中: {week_date}")
    print(f"{'='*50}")

    kev = fetch_kev_for_week(week_date)
    # JPCERT/JVNはRSSのため過去分は取得不可
    jpcert = []
    jvn = []

    print(
        f"KEV: {len(kev)}件 "
        f"(JPCERT/JVN: 過去分取得不可)"
    )

    # 重要度カウント
    counts = {
        "CRITICAL": 0, "高": 0,
        "中": 0, "低": 0
    }
    for v in kev:
        counts["CRITICAL"] += 1

    # vuln_history に追加
    vulns = history["vulnerabilities"]
    new_count = 0
    for v in kev:
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
                "first_seen": week_date,
                "is_major": is_major_vulnerability(v),
                "feature_created": False,
                "source_url": (
                    "https://www.cisa.gov/"
                    "known-exploited-vulnerabilities-catalog"
                )
            }
            new_count += 1

    print(f"履歴追加: {new_count}件")

    # data.json に追加(既存がなければ)
    if week_date not in all_data:
        all_data[week_date] = {
            "date": week_date,
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
                for v in kev
            ],
            "jpcert": [],
            "jvn": []
        }
        print(f"data.json: {week_date} を追加")
    else:
        print(f"data.json: {week_date} は既存のためスキップ")

    # アーカイブHTML生成
    archive_path = f"{DOCS_DIR}/{week_date}.html"
    if not os.path.exists(archive_path):
        html = build_html_content(
            week_date, kev, jpcert, jvn,
            counts, history, is_archive=True
        )
        with open(archive_path, "w",
                  encoding="utf-8") as f:
            f.write(html)
        print(f"✅ {week_date}.html 生成完了")
    else:
        print(f"✅ {week_date}.html は既存のためスキップ")

    return history, all_data


def generate_all_feature_pages_backfill(history):
    """特集ページを全件生成"""
    os.makedirs(FEATURE_DIR, exist_ok=True)
    vulns = history["vulnerabilities"]
    created = []

    for key, vuln in vulns.items():
        if (vuln.get("severity") == "CRITICAL" and
                vuln.get("is_major", False) and
                vuln.get("type") == "kev"):

            safe_id = vuln["id"].replace(
                "/", "-").replace(":", "-"
            ).replace(" ", "-")
            filepath = f"{FEATURE_DIR}/{safe_id}.html"

            if not os.path.exists(filepath):
                generate_feature_page(vuln)
                vuln["feature_created"] = True
                created.append((key, vuln, filepath))
            else:
                vuln["feature_created"] = True

    print(f"\n✅ 特集ページ: {len(created)}件新規生成")
    return created


def main():
    print("📡 バックフィル開始")
    print(f"対象期間: {BACKFILL_DATES[0]} 〜 最新")

    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(FEATURE_DIR, exist_ok=True)

    # 既存データを読み込む
    history = load_vuln_history()
    print(
        f"既存履歴: "
        f"{len(history['vulnerabilities'])}件"
    )

    # 既存のdata.jsonを読み込む
    json_path = f"{DOCS_DIR}/data.json"
    if os.path.exists(json_path):
        with open(json_path, "r",
                  encoding="utf-8") as f:
            all_data = json.load(f)
        print(f"既存週次データ: {len(all_data)}週分")
    else:
        all_data = {}

    # 各週を処理
    for week_date in BACKFILL_DATES:
        history, all_data = backfill_week(
            week_date, history, all_data
        )

    # 特集ページを一括生成
    print("\n📋 特集ページを生成中...")
    feature_pages = generate_all_feature_pages_backfill(
        history
    )

    # 履歴を保存
    save_vuln_history(history)

    # data.jsonを保存
    with open(json_path, "w",
              encoding="utf-8") as f:
        json.dump(all_data, f,
                  ensure_ascii=False, indent=2)
    print(f"✅ data.json 保存完了 ({len(all_data)}週分)")

    # 最新のindex.htmlを再生成
    # (90日以内のCRITICALが増えるため)
    today = datetime.now().strftime("%Y-%m-%d")
    latest_kev = []
    # 最新週のKEVを取得
    if today in all_data:
        latest_kev_raw = all_data[today].get("kev", [])
        for v in latest_kev_raw:
            latest_kev.append({
                "cveID": v["cveID"],
                "product": v["product"],
                "vendorProject": v["vendorProject"],
                "shortDescription": v["description"],
                "dateAdded": v["dateAdded"],
                "dueDate": v["dueDate"],
            })

    counts_today = {
        "CRITICAL": len(latest_kev),
        "高": 0, "中": 0, "低": 0
    }

    html = build_html_content(
        today, latest_kev, [], [],
        counts_today, history,
        is_archive=False
    )
    with open(f"{DOCS_DIR}/index.html",
              "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ index.html 再生成完了")

    # アーカイブ一覧を更新
    generate_archive_index(all_data, [
        (k, v, f"{FEATURE_DIR}/{v['id'].replace('/', '-').replace(':', '-').replace(' ', '-')}.html")
        for k, v in history["vulnerabilities"].items()
        if v.get("feature_created")
    ])

    # プライバシーポリシー
    generate_privacy_policy()

    print("\n=== バックフィル完了 ===")
    print(f"週次累計: {len(all_data)}週分")
    print(
        f"脆弱性履歴: "
        f"{len(history['vulnerabilities'])}件"
    )
    print(f"特集ページ: {len(feature_pages)}件新規生成")


main()
