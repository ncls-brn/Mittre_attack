from dataclasses import dataclass
from typing import List, Dict, Optional
import json
from pathlib import Path

@dataclass
class AppSecMapping:
    owasp: List[str]
    vuln_examples: List[str]
    log_signals: List[str]

@dataclass
class Technique:
    technique_id: str
    name: str
    tactic: str
    description: str
    appsec_mapping: AppSecMapping

class AttckRepository:
    def __init__(self, json_path: str):
        self.json_path = Path(json_path)
        self.techniques: List[Technique] = []
        self._load()

    def _load(self) -> None:
        data = json.loads(self.json_path.read_text(encoding="utf-8"))
        self.techniques = []
        for t in data:
            mapping = AppSecMapping(**t["appsec_mapping"])
            self.techniques.append(
                Technique(
                    technique_id=t["technique_id"],
                    name=t["name"],
                    tactic=t["tactic"],
                    description=t["description"],
                    appsec_mapping=mapping
                )
            )

    def list_tactics(self) -> List[str]:
        return sorted({t.tactic for t in self.techniques})

    def get_by_tactic(self, tactic: str) -> List[Technique]:
        return [t for t in self.techniques if t.tactic.lower() == tactic.lower()]

    def search(self, keyword: str) -> List[Technique]:
        key = keyword.lower()
        result = []
        for t in self.techniques:
            if key in t.technique_id.lower():
                result.append(t)
                continue
            if key in t.name.lower():
                result.append(t)
                continue
            if key in t.description.lower():
                result.append(t)
                continue
        return result

    def get(self, technique_id: str) -> Optional[Technique]:
        for t in self.techniques:
            if t.technique_id.lower() == technique_id.lower():
                return t
        return None
