# sync_attck.py
import json
import requests
from pathlib import Path

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

BASE_DIR = Path(__file__).resolve().parent
RAW_PATH = BASE_DIR / "data" / "enterprise-attack.raw.json"
APPSEC_PATH = BASE_DIR / "data" / "attck_appsec.json"


def download_enterprise_attack() -> None:
    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Téléchargement depuis {MITRE_ENTERPRISE_URL}")
    resp = requests.get(MITRE_ENTERPRISE_URL, timeout=30)
    resp.raise_for_status()
    RAW_PATH.write_text(resp.text, encoding="utf-8")
    print(f"Fichier brut enregistré dans {RAW_PATH}")


def extract_mitre_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract_main_tactic(obj: dict) -> str:
    phases = obj.get("kill_chain_phases", [])
    if not phases:
        return "unknown"
    # MITRE utilise des noms de phase type "initial-access"
    return phases[0].get("phase_name", "unknown")


def build_appsec_json() -> None:
    print(f"Lecture de {RAW_PATH}")
    data = json.loads(RAW_PATH.read_text(encoding="utf-8"))

    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tech_id = extract_mitre_external_id(obj)
        if not tech_id:
            continue

        tactic = extract_main_tactic(obj)

        techniques.append(
            {
                "technique_id": tech_id,
                "name": obj.get("name", ""),
                "tactic": tactic,
                "description": obj.get("description", ""),
                "appsec_mapping": {
                    "owasp": [],
                    "vuln_examples": [],
                    "log_signals": [],
                },
            }
        )

    APPSEC_PATH.parent.mkdir(parents=True, exist_ok=True)
    APPSEC_PATH.write_text(
        json.dumps(techniques, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"{len(techniques)} techniques exportées dans {APPSEC_PATH}")


def main() -> None:
    download_enterprise_attack()
    build_appsec_json()


if __name__ == "__main__":
    main()
