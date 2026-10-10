
"""
BlueSentinel XDR - MITRE ATT&CK Mapper

Maps technique IDs from detection results and alerts to
MITRE ATT&CK technique names and tactics.

The built-in catalogue is intentionally small and can be
expanded using verified MITRE ATT&CK data.
"""

from dataclasses import asdict, dataclass
from typing import Any


# Starter catalogue. Verify and expand this catalogue against
# the official MITRE ATT&CK knowledge base as the project grows.
ATTACK_CATALOGUE = {
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactics": ["Command and Control"],
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactics": ["Lateral Movement"],
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactics": ["Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
}


@dataclass
class MitreMapping:
    """MITRE ATT&CK details for a technique ID."""

    technique_id: str
    technique_name: str
    tactics: list[str]
    url: str | None = None
    known: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly dictionary."""
        return asdict(self)


def _to_dict(item: Any) -> dict[str, Any]:
    """Convert supported objects to dictionaries."""

    if isinstance(item, dict):
        return item

    if hasattr(item, "model_dump"):
        result = item.model_dump(mode="json")
        if isinstance(result, dict):
            return result

    if hasattr(item, "dict") and callable(item.dict):
        result = item.dict()
        if isinstance(result, dict):
            return result

    if hasattr(item, "__dataclass_fields__"):
        return asdict(item)

    raise TypeError(
        "Input must be a dictionary, Pydantic model, or dataclass"
    )


class MitreAttackMapper:
    """Map ATT&CK technique IDs to known names and tactics."""

    def __init__(
        self,
        catalogue: dict[str, dict[str, Any]] | None = None,
    ):
        self.catalogue = (
            ATTACK_CATALOGUE if catalogue is None else catalogue
        )

    def map_technique(self, technique_id: str) -> MitreMapping:
        """Map one technique ID; preserve unknown IDs safely."""

        if not isinstance(technique_id, str):
            raise TypeError("technique_id must be a string")

        technique_id = technique_id.strip().upper()

        if not technique_id:
            raise ValueError("technique_id cannot be empty")

        details = self.catalogue.get(technique_id)

        if details is None:
            return MitreMapping(
                technique_id=technique_id,
                technique_name="Unknown technique",
                tactics=[],
                url=None,
                known=False,
            )

        return MitreMapping(
            technique_id=technique_id,
            technique_name=details["name"],
            tactics=list(details.get("tactics", [])),
            url=details.get("url"),
            known=True,
        )

    def map_techniques(
        self,
        technique_ids: list[str],
    ) -> list[MitreMapping]:
        """Map multiple technique IDs and remove duplicates."""

        mappings = []
        seen = set()

        for technique_id in technique_ids:
            mapping = self.map_technique(technique_id)

            if mapping.technique_id not in seen:
                seen.add(mapping.technique_id)
                mappings.append(mapping)

        return mappings

    def map_detection(self, detection: Any) -> list[MitreMapping]:
        """Map the MITRE technique IDs on a detection result."""

        data = _to_dict(detection)
        technique_ids = data.get("mitre_techniques") or []

        if isinstance(technique_ids, str):
            technique_ids = [technique_ids]

        if not isinstance(technique_ids, (list, tuple, set)):
            raise TypeError("mitre_techniques must be a list of IDs")

        return self.map_techniques(list(technique_ids))

    def map_alert(self, alert: Any) -> list[MitreMapping]:
        """Map the MITRE technique IDs on a security alert."""

        data = _to_dict(alert)
        technique_ids = data.get("mitre_techniques") or []

        if isinstance(technique_ids, str):
            technique_ids = [technique_ids]

        if not isinstance(technique_ids, (list, tuple, set)):
            raise TypeError("mitre_techniques must be a list of IDs")

        return self.map_techniques(list(technique_ids))
