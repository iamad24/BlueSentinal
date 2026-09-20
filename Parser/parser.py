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
        """
        Parse a raw event into a SecurityEvent.

        Parameters
        ----------
        raw_event:
            Raw security event represented as a dictionary.

        Returns
        -------
        SecurityEvent
            Normalized security event.
        """

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

    # =========================================================
    # Timestamp
    # =========================================================

    @staticmethod
    def _extract_timestamp(
        raw_event: dict[str, Any],
    ):
        """
        Extract the event timestamp.

        The detailed timestamp normalization will be
        implemented in normalizer.py.
        """

        timestamp = (
            raw_event.get("timestamp")
            or raw_event.get("Timestamp")
            or raw_event.get("@timestamp")
            or raw_event.get("time")
        )

        if timestamp is None:
            raise ValueError(
                "Raw event does not contain a timestamp."
            )

        return timestamp

    # =========================================================
    # Host
    # =========================================================

    @staticmethod
    def _extract_host(
        raw_event: dict[str, Any],
    ) -> str:
        """
        Extract the hostname from the raw event.
        """

        host = (
            raw_event.get("host")
            or raw_event.get("hostname")
            or raw_event.get("Computer")
            or raw_event.get("computer")
        )

        if not host:
            return "UNKNOWN"

        return str(host)

    # =========================================================
    # Operating System
    # =========================================================

    @staticmethod
    def _extract_os(
        raw_event: dict[str, Any],
    ) -> str:
        """
        Determine the operating system from the raw event.
        """

        os_name = (
            raw_event.get("os")
            or raw_event.get("OS")
            or raw_event.get("platform")
        )

        if os_name:
            return str(os_name).lower()

        # Windows-specific indicators
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

        # Linux-specific indicators
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

    # =========================================================
    # Event Type Detection
    # =========================================================

    @classmethod
    def _detect_event_type(
        cls,
        raw_event: dict[str, Any],
    ) -> str:
        """
        Determine the normalized event type.

        The parser uses observable fields rather than
        assuming that every event has the same structure.
        """

        explicit_type = (
            raw_event.get("event_type")
            or raw_event.get("eventType")
            or raw_event.get("type")
        )

        if explicit_type:
            return str(explicit_type).lower()

        # -----------------------------------------------------
        # PowerShell
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # Process creation
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # Network activity
        # -----------------------------------------------------

        if any(
            key in raw_event
            for key in (
                "source_ip",
                "destination_ip",
                "src_ip",
                "dst_ip",
                "SourceIp",
                "DestinationIp",
            )
        ):
            return "network_connection"

        # -----------------------------------------------------
        # Registry activity
        # -----------------------------------------------------

        if any(
            key in raw_event
            for key in (
                "registry_key",
                "RegistryKey",
                "TargetObject",
            )
        ):
            return "registry_event"

        # -----------------------------------------------------
        # File activity
        # -----------------------------------------------------

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

    # =========================================================
    # Log Source
    # =========================================================

    @staticmethod
    def _detect_log_source(
        raw_event: dict[str, Any],
    ) -> str:
        """
        Determine the source that produced the telemetry.
        """

        explicit_source = (
            raw_event.get("log_source")
            or raw_event.get("logsource")
            or raw_event.get("source")
        )

        if explicit_source:
            return str(explicit_source).lower()

        # Wazuh alerts
        if (
            "rule" in raw_event
            and (
                "agent" in raw_event
                or "manager" in raw_event
            )
        ):
            return "wazuh"

        # Sysmon indicators
        if raw_event.get("Channel") == "Microsoft-Windows-Sysmon/Operational":
            return "sysmon"

        if raw_event.get("ProviderName") == "Microsoft-Windows-Sysmon":
            return "sysmon"

        # Windows Event Log indicators
        if any(
            key in raw_event
            for key in (
                "EventID",
                "EventId",
                "EventRecordID",
            )
        ):
            return "windows"

        # Linux
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