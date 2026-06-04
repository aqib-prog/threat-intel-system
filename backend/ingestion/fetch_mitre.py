import requests
import json
import os

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def fetch_mitre_data():
    print("Fetching MITRE data")
    response = requests.get(MITRE_URL)
    data = response.json()

    # Save raw data
    os.makedirs("data", exist_ok=True)
    with open("data/mitre_raw.json", "w") as f:
        json.dump(data, f)

    print(f"Done Fetched {len(data['objects'])} objects")
    return data

# Attack Patterns


def parse_attack_patterns(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "kill_chain_phases": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
        })
    return results


def parse_intrusion_sets(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "aliases": obj.get("aliases", [])
        })
    return results


def parse_malware(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "malware":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "platforms": obj.get("x_mitre_platforms", []),
            "aliases": obj.get("x_mitre_aliases", [])
        })

    return results


def parse_tools(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "tool":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "platforms": obj.get("x_mitre_platforms", []),
            "aliases": obj.get("x_mitre_aliases", [])
        })
    return results


def parse_course_of_actions(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "course-of-action":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url
        })
    return results


def parse_tactics(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "shortname": obj.get("x_mitre_shortname")
        })
    return results


def parse_campaigns(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "campaign":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
        })
    return results


def parse_data_components(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "x-mitre-data-component":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "log_sources": obj.get("x_mitre_log_sources", []),
        })
    return results


def parse_analytics(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "x-mitre-analytic":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        data_component_refs = [
            ref["x_mitre_data_component_ref"]
            for ref in obj.get("x_mitre_log_source_references", [])
            if "x_mitre_data_component_ref" in ref
        ]
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "external_id": external_id,
            "url": url,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_component_refs": data_component_refs
        })
    return results


def parse_detection_strategies(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "x-mitre-detection-strategy":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = next((r["external_id"]
                           for r in external_refs if "external_id" in r), None)
        url = next((r["url"] for r in external_refs if r.get(
            "source_name") == "mitre-attack"), None)
        results.append({
            "id": obj.get("id"),
            "name": obj.get("name"),
            "external_id": external_id,
            "url": url,
            "analytic_refs": obj.get("x_mitre_analytic_refs", [])
        })
    return results


def parse_relationships(data):
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "relationship":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        results.append({
            "source_ref": obj.get("source_ref"),
            "target_ref": obj.get("target_ref"),
            "relationship_type": obj.get("relationship_type")
        })
    return results


def saved_parsed_data(output_dir="data/parsed"):
    os.makedirs(output_dir, exist_ok=True)
    data = json.load(open("data/mitre_raw.json"))

    parsed = {
        "techniques": parse_attack_patterns(data),
        "actors": parse_intrusion_sets(data),
        "malware": parse_malware(data),
        "tools": parse_tools(data),
        "mitigations": parse_course_of_actions(data),
        "tactics": parse_tactics(data),
        "campaigns": parse_campaigns(data),
        "data_components": parse_data_components(data),
        "analytics": parse_analytics(data),
        "detection_strategies": parse_detection_strategies(data),
        "relationships": parse_relationships(data)
    }

    for name, items in parsed.items():
        with open(f"{output_dir}/{name}.json", "w") as f:
            json.dump(items, f, indent=2)
        print(f"Saved {len(items)} {name}")

    return parsed


if __name__ == "__main__":
    data = json.load(open("data/mitre_raw.json"))
    saved_parsed_data()
