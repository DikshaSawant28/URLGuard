import requests
import base64
import time
import os

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    data = {
        "url": url
    }

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=30
        )

        if response.status_code != 200:
            return None

        analysis_id = response.json()["data"]["id"]

        # Give VirusTotal more time to complete the analysis
        for _ in range(10):
            time.sleep(3)

            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30
            )

            if result.status_code == 200:
                result_data = result.json()["data"]
                status = result_data["attributes"]["status"]

                if status == "completed":
                    stats = result_data["attributes"]["stats"]

                    return (
                        f"Malicious: {stats['malicious']}\n"
                        f"Suspicious: {stats['suspicious']}\n"
                        f"Harmless: {stats['harmless']}\n"
                        f"Undetected: {stats['undetected']}\n\n"
                        f"Report: https://www.virustotal.com/gui/url/{url_id}/detection"
                    )

        return None

    except requests.RequestException:
        return None