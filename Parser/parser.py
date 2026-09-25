from typing import Any

from Engine.detection.models import SecurityEvent


class LogParser:
    """
    Parses raw security telemetry and converts it into
    a normalized SecurityEvent.

    The parser is designed to accept telemetry from
    different sources such as:

    - Windows Event Logs
    - Sysmon
    - PowerShell
    - Wazuh
    - Linux logs

    Event-specific fields remain optional because
    different telemetry types contain different data.
    """

    def parse(
        self,
        raw_event: dict[str, Any],
    ) -> SecurityEvent:
        if not isinstance(raw_event, dict):
            raise TypeError(
                "raw_event must be a dictionary."
            )

        timestamp = self._extract_timestamp(raw_event)
        host = self._extract_host(raw_event)
        os_name = self._extract_os(raw_event)
        event_type = self._detect_event_type(raw_event)
        log_source = self._detect_log_source(raw_event)

        return SecurityEvent(
            timestamp=timestamp,
            host=host,
            os=os_name,
            event_type=event_type,
            log_source=log_source,
            raw_event=raw_event,
        )

    @staticmethod
    def _extract_timestamp(
        raw_event: dict[str, Any],
    ):
        """
        Extract the event timestamp.

        Supports common timestamp field names used by:

        - Wazuh
        - Windows Event Logs
        - Sysmon
        - Generic JSON telemetry
        """

        timestamp = (
            raw_event.get("timestamp")
            or raw_event.get("Timestamp")
            or raw_event.get("@timestamp")
            or raw_event.get("time")
            or raw_event.get("TimeCreated")
        )

        if timestamp is None:
            raise ValueError(
                "Raw event does not contain a timestamp."
            )

        return timestamp

    @staticmethod
    def _extract_host(
        raw_event: dict[str, Any],
    ) -> str:
        host = (
            raw_event.get("host")
            or raw_event.get("hostname")
            or raw_event.get("Computer")
            or raw_event.get("computer")
        )

        if not host:
            return "UNKNOWN"

        return str(host)

    @staticmethod
    def _extract_os(
        raw_event: dict[str, Any],
    ) -> str:
        os_name = (
            raw_event.get("os")
            or raw_event.get("OS")
            or raw_event.get("platform")
        )

        if os_name:
            return str(os_name).lower()

        if any(
            key in raw_event
            for key in (
                "EventID",
                "EventId",
                "ScriptBlockText",
                "Image",
                "CommandLine",
            )
        ):
            return "windows"

        if any(
            key in raw_event
            for key in (
                "syslog",
                "syslog_message",
                "journal",
            )
        ):
            return "linux"

        return "unknown"

    @classmethod
    def _detect_event_type(
        cls,
        raw_event: dict[str, Any],
    ) -> str:
        explicit_type = (
            raw_event.get("event_type")
            or raw_event.get("eventType")
            or raw_event.get("type")
        )

        if explicit_type:
            return str(explicit_type).lower()

        # PowerShell / Script Block events
        if any(
            key in raw_event
            for key in (
                "ScriptBlockText",
                "script_block_text",
                "PowerShell",
                "powershell",
            )
        ):
            return "powershell_script"

        # Process creation events
        if (
            raw_event.get("EventID") in (1, "1")
            or raw_event.get("EventId") in (1, "1")
        ):
            return "process_creation"

        if any(
            key in raw_event
            for key in (
                "process",
                "ProcessId",
                "ParentProcessId",
                "Image",
                "CommandLine",
            )
        ):
            return "process_creation"

        # Network events
        if any(
            key in raw_event
            for key in (
                "source_ip",
                "destination_ip",
                "src_ip",
                "dst_ip",
                "SourceIp",
                "DestinationIp",
                "SourceIP",
                "DestinationIP",
            )
        ):
            return "network_connection"

        # Registry events
        if any(
            key in raw_event
            for key in (
                "registry_key",
                "RegistryKey",
                "TargetObject",
            )
        ):
            return "registry_event"

        # File events
        if any(
            key in raw_event
            for key in (
                "file_path",
                "FileName",
                "TargetFilename",
            )
        ):
            return "file_event"

        return "unknown"

    @staticmethod
    def _detect_log_source(
        raw_event: dict[str, Any],
    ) -> str:
        explicit_source = (
            raw_event.get("log_source")
            or raw_event.get("logsource")
            or raw_event.get("source")
        )

        if explicit_source:
            return str(explicit_source).lower()

        # Wazuh event
        if (
            "rule" in raw_event
            and (
                "agent" in raw_event
                or "manager" in raw_event
            )
        ):
            return "wazuh"

        # Sysmon events
        if (
            raw_event.get("Channel")
            == "Microsoft-Windows-Sysmon/Operational"
        ):
            return "sysmon"

        if (
            raw_event.get("ProviderName")
            == "Microsoft-Windows-Sysmon"
        ):
            return "sysmon"

        # Windows Event Logs
        if any(
            key in raw_event
            for key in (
                "EventID",
                "EventId",
                "EventRecordID",
            )
        ):
            return "windows"

        # Linux logs
        if any(
            key in raw_event
            for key in (
                "syslog",
                "syslog_message",
                "journal",
            )
        ):
            return "linux"

        return "unknown"


if __name__ == "__main__":
    print("BlueSentinel Log Parser")
    print("-" * 30)