import argparse 
import sys

from ioc_detector import detect_ioc_type
from enrichment.virustotal import check_hash_vt
from enrichment.virustotal import check_url_vt

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Type URL, IP,  hash, or domain")
    parser.add_argument("ioc", help="URL, IP,  hash, or domain")
    return parser.parse_args(argv)

def main(argv=None) -> None:
    args = parse_args(argv)
    ioc = args.ioc
    ioc_type = detect_ioc_type(ioc)

    # call virustotal url lookup
    if ioc_type == "url":
        result = check_url_vt(ioc)              
    # call abuseipdb + whois      
    elif ioc_type == "ip":
        # coming soon
        return    
    # call virustotal hash lookup    
    elif ioc_type in ["md5", "sha1", "sha256"]:
        result = check_hash_vt(ioc)        
    # call virustotal domain lookup + whois     
    elif ioc_type == "domain":
        # coming soon
        return
        
    else:
        print("Unknown IOC type")
        raise SystemExit(1)
    
    print(result)

if __name__ == "__main__":
    main()