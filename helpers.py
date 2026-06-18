from typing import Any

def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")

def vt_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 1:
        return "MALICIOUS"
    elif suspicious >= 1:
        return "SUSPICIOUS"
    return "CLEAN"

def ip_verdict(abuse_score: int) -> str:
    if abuse_score >= 80:
        return "MALICIOUS"
    elif abuse_score >= 25:
        return "SUSPICIOUS"
    return "CLEAN"

def print_otx(results: dict) -> None:
    otx = results.get("otx", {})
    print_field("OTX Pulse Count:", otx.get("pulse_count", "Unknown"))
    print_field("OTX Malware Families:", ", ".join(otx.get("malware_families", [])) or "None")
    print_field("OTX Adversaries:", ", ".join(otx.get("adversaries", [])) or "None")
    print_field("OTX Validation:", ", ".join(otx.get("validation", [])) or "None")