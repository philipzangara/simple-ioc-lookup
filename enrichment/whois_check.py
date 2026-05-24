import whois

def check_whois(ioc: str) -> dict:
    w = whois.whois(ioc)

    return {
        "ioc": ioc,
        "type": "whois",
        "domain_name": w.domain_name,
        "registrar": w.registrar,
        "org": w.org,
        "country": w.country,
        "creation_date": w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date,
        "expiration_date": w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date,
        "updated_date": w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date,
        "name_servers": w.name_servers[:2] if w.name_servers else []
    }