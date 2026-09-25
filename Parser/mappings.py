"""
BlueSentinel field and telemetry mappings.

This module centralizes the different field names used by
Windows Event Logs, Sysmon, Wazuh, and Linux telemetry.

The parser and normalizer can use these mappings instead
of maintaining duplicate field-name definitions.
"""


# =========================================================
# Common field mappings
# =========================================================

COMMON_FIELD_MAPPINGS = {
    "timestamp": [
        "timestamp",
        "@timestamp",
        "Timestamp",
        "TimeCreated",
        "time",
    ],

    "host": [
        "host",
        "hostname",
        "Computer",
        "computer",
    ],

    "os": [
        "os",
        "OS",
        "platform",
        "OperatingSystem",
    ],

    "event_type": [
        "event_type",
        "eventType",
        "event.type",
        "type",
    ],

    "log_source": [
        "log_source",
        "logsource",
        "source",
    ],

    "user": [
        "user",
        "username",
        "User",
        "UserName",
        "TargetUserName",
    ],
}


# =========================================================
# Process mappings
# =========================================================

PROCESS_FIELD_MAPPINGS = {
    "process": [
        "process",
        "process_name",
        "ProcessName",
        "Image",
    ],

    "process_id": [
        "process_id",
        "ProcessId",
        "ProcessID",
    ],

    "parent_process": [
        "parent_process",
        "parent_process_name",
        "ParentImage",
    ],

    "parent_process_id": [
        "parent_process_id",
        "ParentProcessId",
        "ParentProcessID",
    ],

    "command_line": [
        "command_line",
        "CommandLine",
        "process_command_line",
    ],
}


# =========================================================
# PowerShell mappings
# =========================================================

POWERSHELL_FIELD_MAPPINGS = {
    "script_block_text": [
        "script_block_text",
        "ScriptBlockText",
        "ScriptBlock",
    ],

    "powershell": [
        "PowerShell",
        "powershell",
    ],
}


# =========================================================
# Network mappings
# =========================================================

NETWORK_FIELD_MAPPINGS = {
    "source_ip": [
        "source_ip",
        "src_ip",
        "SourceIp",
        "SourceIP",
    ],

    "destination_ip": [
        "destination_ip",
        "dst_ip",
        "DestinationIp",
        "DestinationIP",
    ],

    "source_port": [
        "source_port",
        "src_port",
        "SourcePort",
    ],

    "destination_port": [
        "destination_port",
        "dst_port",
        "DestinationPort",
    ],

    "protocol": [
        "protocol",
        "Protocol",
    ],
}


# =========================================================
# File mappings
# =========================================================

FILE_FIELD_MAPPINGS = {
    "file_path": [
        "file_path",
        "FileName",
        "TargetFilename",
    ],

    "file_hash": [
        "file_hash",
        "hash",
        "Hash",
        "SHA256",
        "SHA1",
        "MD5",
    ],
}


# =========================================================
# Registry mappings
# =========================================================

REGISTRY_FIELD_MAPPINGS = {
    "registry_key": [
        "registry_key",
        "RegistryKey",
        "TargetObject",
    ],

    "registry_value": [
        "registry_value",
        "RegistryValueName",
        "ValueName",
    ],
}


# =========================================================
# Windows Event mappings
# =========================================================

WINDOWS_FIELD_MAPPINGS = {
    "event_id": [
        "EventID",
        "EventId",
        "event_id",
    ],

    "event_record_id": [
        "EventRecordID",
        "event_record_id",
    ],

    "channel": [
        "Channel",
        "channel",
    ],

    "provider": [
        "ProviderName",
        "provider",
    ],
}


# =========================================================
# Wazuh mappings
# =========================================================

WAZUH_FIELD_MAPPINGS = {
    "rule": [
        "rule",
    ],

    "agent": [
        "agent",
    ],

    "manager": [
        "manager",
    ],

    "decoder": [
        "decoder",
    ],

    "full_log": [
        "full_log",
    ],
}


# =========================================================
# Linux / Syslog mappings
# =========================================================

LINUX_FIELD_MAPPINGS = {
    "syslog": [
        "syslog",
        "syslog_message",
    ],

    "journal": [
        "journal",
    ],

    "facility": [
        "facility",
    ],

    "priority": [
        "priority",
    ],
}


# =========================================================
# Event type mappings
# =========================================================

EVENT_TYPE_MAPPINGS = {
    "powershell": "powershell_script",

    "powershell_script": "powershell_script",

    "ps_script": "powershell_script",

    "process": "process_creation",

    "process_creation": "process_creation",

    "process_start": "process_creation",

    "network": "network_connection",

    "network_connection": "network_connection",

    "dns": "dns",

    "dns_query": "dns",

    "registry": "registry_event",

    "registry_event": "registry_event",

    "file": "file_event",

    "file_event": "file_event",

    "file_creation": "file_event",

    "file_modification": "file_event",
}


# =========================================================
# Operating system mappings
# =========================================================

OS_MAPPINGS = {
    "win": "windows",
    "windows": "windows",
    "windows server": "windows",

    "linux": "linux",
    "unix": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "kali": "linux",

    "mac": "macos",
    "macos": "macos",
    "osx": "macos",
}


# =========================================================
# Telemetry source mappings
# =========================================================

LOG_SOURCE_MAPPINGS = {
    "win": "windows",
    "windows": "windows",

    "sysmon": "sysmon",

    "wazuh": "wazuh",

    "linux": "linux",
    "syslog": "linux",

    "macos": "macos",
    "osx": "macos",
}


# =========================================================
# Combined mappings
# =========================================================

FIELD_MAPPINGS = {
    **COMMON_FIELD_MAPPINGS,
    **PROCESS_FIELD_MAPPINGS,
    **POWERSHELL_FIELD_MAPPINGS,
    **NETWORK_FIELD_MAPPINGS,
    **FILE_FIELD_MAPPINGS,
    **REGISTRY_FIELD_MAPPINGS,
    **WINDOWS_FIELD_MAPPINGS,
    **WAZUH_FIELD_MAPPINGS,
    **LINUX_FIELD_MAPPINGS,
}


if __name__ == "__main__":
    print("BlueSentinel Field Mappings")
    print("-" * 32)

    print(
        f"Common fields: "
        f"{len(COMMON_FIELD_MAPPINGS)}"
    )

    print(
        f"Process fields: "
        f"{len(PROCESS_FIELD_MAPPINGS)}"
    )

    print(
        f"PowerShell fields: "
        f"{len(POWERSHELL_FIELD_MAPPINGS)}"
    )

    print(
        f"Network fields: "
        f"{len(NETWORK_FIELD_MAPPINGS)}"
    )

    print(
        f"File fields: "
        f"{len(FILE_FIELD_MAPPINGS)}"
    )

    print(
        f"Registry fields: "
        f"{len(REGISTRY_FIELD_MAPPINGS)}"
    )

    print(
        f"Total normalized fields: "
        f"{len(FIELD_MAPPINGS)}"
    )