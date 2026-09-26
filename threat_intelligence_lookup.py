#Threat Intelligence Lookup Tool Project
#API_KEY should not be stored locally

import sys
import ipaddress
import requests
import os
import re
from datetime import datetime
from urllib.parse import urlparse
import base64


def main():
    if len(sys.argv) != 3:
        sys.exit("""Usage:
        program <indicator> <target>
        program batch <filename>

        Indicator:
        ip | domain | url | hash""")

    operation = sys.argv[1]
    query_target = sys.argv[2]

    if operation == "batch":
        targets = batch_processing(query_target)
    else:
        targets = [validate_input(query_target)]

    for valid_target, indicator_type in targets:
        error_message = None
        try:
            data = query_virustotal(indicator_type, valid_target)
        except requests.exceptions.ConnectionError:
            error_message = "Connection not established/complete"
        except requests.exceptions.HTTPError:
            error_message = "Unsuccessful HTTP response from VirusTotal"
        except requests.exceptions.JSONDecodeError:
            error_message = "Could not decode response into .json format"
        if error_message is not None:
            if operation == "batch":
                print(error_message)
                continue
            else:
                sys.exit(error_message)
        

        query_info = process_data(data)
        score, threat_level = assess_threat(query_info)
        report = generate_report(indicator_type, valid_target, query_info, score, threat_level)
        print(report)
        write_report(report)


def validate_input(query_target):
    is_ip = True
    parsed_url = urlparse(query_target)

    try:
        ipaddress.ip_address(query_target)
    except ValueError:
        is_ip = False
    if is_ip:
        indicator_type = "ip"

    elif re.fullmatch(r"[A-Za-z0-9-]+\.[A-Za-z]{3}", query_target):
        indicator_type = "domain"

    elif parsed_url.scheme  in ("http", "https") and parsed_url.hostname is not None:
        indicator_type = "url"

    elif re.fullmatch(r"([a-fA-F0-9]){32}|([a-fA-F0-9]){40}|([a-fA-F0-9]){64}", query_target):
        indicator_type = "hash"
    else:
        sys.exit("""Usage:
        program <indicator> <target>
        program batch <filename>

        Indicator:
        ip | domain | url | hash""")

    valid_target = query_target
    
    return valid_target, indicator_type


def query_virustotal(indicator_type, valid_target):
    API_KEY = os.environ["API_KEY"]
    header = {"x-apikey": API_KEY}

    if indicator_type == "ip":
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{valid_target}", headers=header)
    elif indicator_type == "domain":
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{valid_target}", headers=header)
    elif indicator_type == "url":
        url_query = base64.urlsafe_b64encode(valid_target.encode()).decode()
        url_query = url_query.rstrip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_query}", headers=header)
    elif indicator_type == "hash":
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{valid_target}", headers=header)

    response.raise_for_status()
    data = response.json()

    return data


def process_data(data):
    lookup_attributes = data["data"]["attributes"]
    last_analysis_stats = lookup_attributes.get("last_analysis_stats", {})

    creation_date = lookup_attributes.get("creation_date", "Unavailable")
    if creation_date != "Unavailable":
        creation_date = datetime.fromtimestamp(creation_date)

    return{
    "as_owner": lookup_attributes.get("as_owner", "Unavailable"),
    "asn": lookup_attributes.get("asn", "Unavailable"),
    "country": lookup_attributes.get("country", "Unavailable"),

    "registrar": lookup_attributes.get("registrar", "Unavailable"),
    "creation_date": creation_date,

    "title": lookup_attributes.get("title", "Unavailable"),
    "last_final_url": lookup_attributes.get("last_final_url", "Unavailable"),

    "filename": lookup_attributes.get("meaningful_name", "Unavailable"),
    "filetype": lookup_attributes.get("type_description", "Unavailable"),
    "md5": lookup_attributes.get("md5", "Unavailable"),
    "sha1": lookup_attributes.get("sha1", "Unavailable"),
    "sha256": lookup_attributes.get("sha256", "Unavailable"),

    "reputation": lookup_attributes.get("reputation", "Unavailable"),
    "malicious_count": last_analysis_stats.get("malicious", "Unavailable"),
    "suspicious_count": last_analysis_stats.get("suspicious", "Unavailable"),
    "undetected_count": last_analysis_stats.get("undetected", "Unavailable"),
    "harmless_count": last_analysis_stats.get("harmless", "Unavailable")
    }


def batch_processing(query_target):
    with open(query_target, "r") as batchfile:
        for entry in batchfile:
            entry = entry.strip()
            if not entry:
                continue

            valid_target, indicator_type = validate_input(entry)

            yield valid_target, indicator_type


def assess_threat(query_info):
    score = 0
    malicious_rules = [
        {"minimum": 0, "maximum": 0, "points": 0},
        {"minimum": 1, "maximum": 2, "points": 2},
        {"minimum": 3, "maximum": 5, "points": 4},
        {"minimum": 6, "maximum": 10, "points": 6},
        {"minimum": 11, "maximum": float("inf"), "points": 8}
    ]
    if query_info["malicious_count"] != "Unavailable":   
        for rule in malicious_rules:
            if query_info["malicious_count"] >= rule["minimum"] and query_info["malicious_count"] <= rule["maximum"]:
                score = score + rule["points"]
                break

    suspicious_rules = [
        {"minimum": 0, "maximum": 0, "points": 0},
        {"minimum": 1, "maximum": 2, "points": 1},
        {"minimum": 3, "maximum": 5, "points": 2},
        {"minimum": 6, "maximum": float("inf"), "points": 3}
    ]
    if query_info["suspicious_count"] != "Unavailable":
        for rule in suspicious_rules:
            if query_info["suspicious_count"] >= rule["minimum"] and query_info["suspicious_count"] <= rule["maximum"]:
                score = score + rule["points"]
                break 

    reputation_rules = [
        {"minimum": 50, "maximum": float("inf"), "points": -2},
        {"minimum": 20, "maximum": 49, "points": -1},
        {"minimum": -19, "maximum": 19, "points": 0},
        {"minimum": -49, "maximum": -20, "points": 1},
        {"minimum": float("-inf"), "maximum": -50, "points": 2}
    ]
    if query_info["reputation"] != "Unavailable":
        for rule in reputation_rules:
            if query_info["reputation"] >= rule["minimum"] and query_info["reputation"] <= rule["maximum"]:
                score = score + rule["points"]
                break 

    threat_levels = [
        {"minimum": float("-inf"), "maximum": 2, "level": "LOW"},
        {"minimum": 3, "maximum": 5, "level": "MEDIUM"},
        {"minimum": 6, "maximum": float("inf"), "level": "HIGH"}
    ]
    for level_rule in threat_levels:
        if score >= level_rule["minimum"] and score <= level_rule["maximum"]:
            threat_level = level_rule["level"]
            break

    return score, threat_level


def generate_report(indicator_type, valid_target, query_info, score, threat_level):
    if indicator_type == "ip":
        report = f"""\n Network Identity\n ------------------\n IP: {valid_target}\n AS Owner: {query_info['as_owner']}\n ASN: {query_info['asn']}\n Country: {query_info['country']}\n"""
    elif indicator_type == "domain":
        report = f"""\n Domain Identity\n ------------------\n Domain: {valid_target}\n Registrar: {query_info['registrar']}\n Creation Date: {query_info['creation_date']}\n"""
    elif indicator_type == "url":
        report = f"""\n URL Identity\n ------------------\n URL: {valid_target}\n Title: {query_info['title']}\n Final URL: {query_info['last_final_url']}\n"""
    elif indicator_type == "hash":
        report = f"""\n Hash Identity\n ------------------\n File Name: {query_info['filename']}\n File Type: {query_info['filetype']}\n MD5: {query_info['md5']}\n SHA-1: {query_info['sha1']}\n SHA-256: {query_info['sha256']}\n"""

    report += f"""\n Reputation\n ------------------\n Reputation: {query_info['reputation']}\n"""
    report += f"""\n Analysis Results\n ------------------\n Malicious: {query_info['malicious_count']}\n Suspicious: {query_info['suspicious_count']}\n Undetected: {query_info['undetected_count']}\n Harmless: {query_info['harmless_count']}\n"""

    report += f"""\n Threat Assessment\n ------------------\n Threat Level: {threat_level}\n Threat Score: {score}\n\n"""

    return report


def write_report(report):
    with open("lookup_report.txt", "a") as reportfile:
        reportfile.write(report)


if __name__ == "__main__":
    main()
