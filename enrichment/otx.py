import requests
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("OTX_API_KEY") or ""

# check IOCs in AlienVault OTX
def check_otx(ioc: str, ioc_type: str) -> dict:

    if not api_key:
        return {"error": "No OTX API key found in .env"}

    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file"
    }

    otx_type = type_map.get(ioc_type)
    if not otx_type:
        return {"error": f"Unsupported IOC type for OTX: {ioc_type}"}

    headers = {"X-OTX-API-KEY": api_key}
    try:
        get_response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general", 
                                    headers=headers) # type: ignore
        response = get_response.json()
        return {
            "ioc": ioc,
            "type": ioc_type,
            "pulse_count": response["pulse_info"]["count"],
            "malware_families": response["pulse_info"]["related"]["alienvault"]["malware_families"],
            "adversaries": response["pulse_info"]["related"]["alienvault"]["adversary"],
            "validation": [v["name"] for v in response.get("validation", [])],
        }
    except Exception as e:
        return {"error": str(e)}
            