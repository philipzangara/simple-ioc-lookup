import ipaddress
import re

def detect_ioc_type(ioc: str) -> str:

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"

    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except (ValueError):
        pass

    # check if hexadecimal
    pattern = r'^[0-9a-fA-F]+$'
    is_hex = re.match(pattern, ioc)

    # check MD5
    if is_hex and len(ioc) == 32:
        return "md5"
    # check SHA1
    elif is_hex and len(ioc) == 40:
        return "sha1"
    # check SHA256
    elif is_hex and len(ioc) == 64:
        return "sha256"
    else:
        return "domain"
