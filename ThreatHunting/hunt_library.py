
"""Built-in threat hunting scenarios for BlueSentinel XDR."""

from typing import Any


BUILT_IN_HUNTS: list[dict[str, Any]] = [
    {
        "id": "TH-001",
        "name": "Suspicious PowerShell Execution",
        "description": (
            "Identify PowerShell commands with potentially "
            "suspicious indicators."
        ),
        "mitre_techniques": ["T1059.001"],
        "field": "command_line",
        "keywords": [
            "powershell",
            "encodedcommand",
            "frombase64string",
            "downloadstring",
            "invoke-expression",
            "iex ",
        ],
        "severity": "high",
    },
    {
        "id": "TH-002",
        "name": "Suspicious Script Interpreter Activity",
        "description": (
            "Identify potentially suspicious script interpreter commands."
        ),
        "mitre_techniques": ["T1059"],
        "field": "process",
        "keywords": [
            "wscript",
            "cscript",
            "mshta",
            "javascript:",
        ],
        "severity": "medium",
    },
    {
        "id": "TH-003",
        "name": "Potential Credential Access",
        "description": (
            "Identify command lines containing credential-access indicators."
        ),
        "mitre_techniques": ["T1003"],
        "field": "command_line",
        "keywords": [
            "lsass",
            "sekurlsa",
            "procdump",
            "comsvcs.dll",
        ],
        "severity": "high",
    },
    {
        "id": "TH-004",
        "name": "Potential Persistence Through Registry",
        "description": (
            "Identify registry activity involving common autorun locations."
        ),
        "mitre_techniques": ["T1547.001"],
        "field": "registry_path",
        "keywords": [
            r"\currentversion\run",
            r"\currentversion\runonce",
        ],
        "severity": "high",
    },
    {
        "id": "TH-005",
        "name": "Potential Discovery Activity",
        "description": (
            "Identify commands commonly associated with system discovery."
        ),
        "mitre_techniques": ["T1082", "T1016"],
        "field": "command_line",
        "keywords": [
            "systeminfo",
            "whoami /all",
            "ipconfig /all",
            "nltest",
            "net group",
        ],
        "severity": "low",
    },
]


def get_builtin_hunts() -> list[dict[str, Any]]:
    """Return copies so callers cannot mutate the built-in definitions."""
    return [
        {
            **hunt,
            "keywords": list(hunt["keywords"]),
            "mitre_techniques": list(hunt["mitre_techniques"]),
        }
        for hunt in BUILT_IN_HUNTS
    ]


def get_hunt_by_id(hunt_id: str) -> dict[str, Any] | None:
    """Find a built-in hunt by its identifier."""
    for hunt in get_builtin_hunts():
        if hunt["id"] == hunt_id:
            return hunt

    return None
