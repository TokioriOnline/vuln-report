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
                 jpcert_list, jvn_list,
                 counts):
    """収集データをJSONで累積保存"""
    json_path = "docs/data.json"

    # 既存データを読み込む
    if os.path.exists(json_path):
        with open(json_path, "r",
                  encoding="utf-8") as f:
            all_data = json.load(f)
    else:
        all_data = {}

    # 今週のデータを追加
    all_data[today] = {
        "date": today,
        "summary": {
            "critical": counts["CRITICAL"],
            "high": counts["高"],
            "medium": counts["中"],
            "low": counts["低"],
            "total":
