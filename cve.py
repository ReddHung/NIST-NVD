#!/usr/bin/env python3
import requests
import sys
import os
from datetime import datetime, timedelta

API_KEY = os.environ.get("API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 50


def fetch_recent_new_cve(keyword=None, limit=RESULTS_PER_PAGE):
    now = datetime.utcnow()
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    params = {
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": limit
    }
    if keyword:
        params["keywordSearch"] = keyword

    headers = {"apiKey": API_KEY}

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        if not r.headers.get("Content-Type", "").startswith("application/json"):
            print("❌ 非 JSON 回應，回傳內容：")
            print(r.text[:300])
            sys.exit(1)
        data = r.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.JSONDecodeError:
        print("❌ JSON 解析錯誤，回傳內容：")
        print(r.text[:300])
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print("❌ HTTP 錯誤:", e, " 回應內容：", r.text[:300])
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print("❌ 請求錯誤:", e)
        sys.exit(1)


def print_results(keyword=None):
    vulns = fetch_recent_new_cve(keyword)
    kw_label = keyword if keyword else "ALL"
    if not vulns:
        print(f"⚠️ 最近 24 小時沒有找到 '{kw_label}' 相關 CVE")
        return

    print(f"\n=== 最近 24 小時新增 CVE: {kw_label} ({len(vulns)} 筆) ===\n")
    for item in vulns:
        cve = item["cve"]
        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"]
        published = cve.get("published", "N/A")
        score = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        print(f"CVE ID: {cve_id} | CVSS: {score}")
        print(f"Published: {published}")
        print(f"Description: {desc}\n")
        print("-" * 60)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 傳入多個 keyword，就依序抓
        for kw in sys.argv[1:]:
            print_results(kw)
    else:
        # 沒有傳參數，抓全部最近 24 小時新增 CVE
        print_results()
