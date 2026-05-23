from typing import Optional, Any

def display_results(results: dict) -> None:
    print("*** IOC Enrichment Report ***")
    if results.get("error"):
        print_field("Error:", results.get("error"))
        return
    print_field("IOC: ", results.get("ioc"))
    print_field("Type: ", results.get("type"))
    print_field("Malicious: ", results.get("malicious"))
    print_field("Suspicious: ", results.get("suspicious"))
    print_field("Harmless: ", results.get("harmless"))
    print_field("Reputation: ", results.get("reputation"))

    if results.get("type") == "hash":
        print_field("Meaningful name:", results.get("meaningful_name"))
        print_field("File Type:", results.get("file_type"))
    elif results.get("type") == "url":
        print_field("Undetected: ", results.get("undetected"))
        print_field("Final URL:", results.get("final_url"))
        print_field("Title:", results.get("title"))

    votes = results.get("total_votes", {})
    print_field("Votes Harmless:", votes.get("harmless", 0))
    print_field("Votes Malicious:", votes.get("malicious", 0))
    
def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")