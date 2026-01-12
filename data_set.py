import requests
import os
import pandas as pd
import time
from datetime import datetime, timedelta


NVD_API_KEY=os.getenv("NVD_API_KEY")
DAYS_BACK = 120    

def fetch_and_save_nvd():
    end_date = datetime.now()
    start_date = end_date - timedelta(days=DAYS_BACK)
    
    # NVD API date format
    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 2000,
        "startIndex": 0
    }
    
    all_vulns = []
    
    
    while True:
        try:
            print(f"   Fetching records starting at index {params['startIndex']}...")
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code != 200:
                print(f" Error {response.status_code}: {response.text}")
                break
                
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
                
            for item in vulnerabilities:
                cve = item.get("cve", {})
                
                # Extract Description
                descriptions = cve.get("descriptions", [])
                desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
                
                # Extract Scores (Prioritize V3.1 > V3.0 > V2.0)
                metrics = cve.get("metrics", {})
                score = 0.0
                severity = "LOW"
                
                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]["cvssData"]
                    score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "LOW")
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]["cvssData"]
                    score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "LOW")
                elif "cvssMetricV2" in metrics:
                    m = metrics["cvssMetricV2"][0]["cvssData"]
                    score = m.get("baseScore", 0.0)
                   
                    severity = "HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW")

                all_vulns.append({
                    "cveID": cve.get("id"),
                    "description": desc_text,
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "baseScore": score,
                    "severity": severity
                })
            
            total_results = data.get("totalResults", 0)
            params["startIndex"] += 2000
            
            if params["startIndex"] >= total_results:
                break
                
            time.sleep(2) 
            
        except Exception as e:
            print(f" Connection error: {e}")
            break

    # Save to CSV
    df = pd.DataFrame(all_vulns)
    filename = "nvd_data.csv"
    df.to_csv(filename, index=False)
    print(f"  Downloaded {len(df)} records to '{filename}'")
   

if __name__ == "__main__":
    fetch_and_save_nvd()