from datetime import datetime, timezone
from typing import Any

from Engine.detection.models import SecurityEvent


class LogNormalizer:
    """
    Normalizes raw security telemetry into the common
    BlueSentinel SecurityEvent structure.

    Different telemetry sources use different field names.
    The normalizer maps those fields into a consistent format.

    Not every event contains every field.
    Missing event-specific fields remain optional.
    """

    # =========================================================
    # Main normalization method
    # =========================================================

    def normalize(
        self,
        raw_event: dict[str, Any],
    ) -> SecurityEvent:
        """
        Convert a raw event dictionary into a SecurityEvent.
        """

        if not isinstance(raw_event, dict):
            raise TypeError(
                "raw_event must be a dictionary."
            )

        return SecurityEvent(
            timestamp=self._normalize_timestamp(raw_event),
            host=self._get_first(
                raw_event,
                "host",
                "hostname",
                "Computer",
                "computer",
            ),
            os=self._normalize_os(raw_event),
            event_type=self._normalize_event_type(raw_event),
            log_source=self._normalize_log_source(raw_event),

            # -------------------------------------------------
            # Optional common fields
            # -------------------------------------------------

            user=self._get_first(
                raw_event,
                "user",
                "username",
                "User",
                "UserName",
                "TargetUserName",
            ),

            process=self._get_first(
                raw_event,
                "process",
                "process_name",
                "ProcessName",
                "Image",
            ),

            process_id=self._get_first(
                raw_event,
                "process_id",
                "ProcessId",
                "ProcessID",
            ),

            parent_process=self._get_first(
                raw_event,
                "parent_process",
                "parent_process_name",
                "ParentImage",
            ),

            parent_process_id=self._get_first(
                raw_event,
                "parent_process_id",
                "ParentProcessId",
                "ParentProcessID",
            ),

            command_line=self._get_first(
                raw_event,
                "command_line",
                "CommandLine",
                "process_command_line",
            ),

            # -------------------------------------------------
            # PowerShell
            # -------------------------------------------------

            script_block_text=self._get_first(
                raw_event,
                "script_block_text",
                "ScriptBlockText",
                "ScriptBlock",
            ),

            # -------------------------------------------------
            # Network
            #
            # These are optional. They will only be populated
            # when the event actually contains network data.
            # -------------------------------------------------

            source_ip=self._get_first(
                raw_event,
                "source_ip",
                "src_ip",
                "SourceIp",
                "SourceIP",
            ),

            destination_ip=self._get_first(
                raw_event,
                "destination_ip",
                "dst_ip",
                "DestinationIp",
                "DestinationIP",
            ),

            source_port=self._get_first(
                raw_event,
                "source_port",
                "src_port",
                "SourcePort",
            ),

            destination_port=self._get_first(
                raw_event,
                "destination_port",
                "dst_port",
                "DestinationPort",
            ),

            protocol=self._get_first(
                raw_event,
                "protocol",
                "Protocol",
            ),

            # -------------------------------------------------
            # File
            # -------------------------------------------------

            file_path=self._get_first(
                raw_event,
                "file_path",
                "FileName",
                "TargetFilename",
            ),

            file_hash=self._get_first(
                raw_event,
                "file_hash",
                "hash",
                "Hash",
                "SHA256",
                "SHA1",
                "MD5",
            ),

            # -------------------------------------------------
            # Registry
            # -------------------------------------------------

            registry_key=self._get_first(
                raw_event,
                "registry_key",
                "RegistryKey",
                "TargetObject",
            ),

            registry_value=self._get_first(
                raw_event,
                "registry_value",
                "RegistryValueName",
                "ValueName",
            ),

            # -------------------------------------------------
            # Preserve original telemetry
            # -------------------------------------------------

            raw_event=raw_event,
        )

    # =========================================================
    # Generic field extraction
    # =========================================================

    @staticmethod
    def _get_first(
        raw_event: dict[str, Any],
        *field_names: str,
    ) -> Any:
        """
        Return the first available field from the supplied
        field-name candidates.
        """

        for field_name in field_names:
            value = raw_event.get(field_name)

            if value is not None:
                return value

        return None

    # =========================================================
    # Timestamp normalization
    # =========================================================

    @classmethod
    def _normalize_timestamp(
        cls,
        raw_event: dict[str, Any],
    ):
        """
        Normalize common timestamp representations.

        Supported examples:

        - datetime object
        - ISO-8601 string
        - timestamp field
        - @timestamp
        - TimeCreated
        """

        value = cls._get_first(
            raw_event,
            "timestamp",
            "@timestamp",
            "Timestamp",
            "TimeCreated",
            "time",
        )

        if value is None:
            return datetime.now(timezone.utc)

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(
                    tzinfo=timezone.utc
                )

            return value

        if isinstance(value, str):
            normalized = value.strip()

            # Convert Zulu time to Python ISO format.
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"

            try:
                parsed = datetime.fromisoformat(
                    normalized
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed

            except ValueError:
                pass

        return datetime.now(timezone.utc)

    # =========================================================
    # Operating system
    # =========================================================

    @classmethod
    def _normalize_os(
        cls,
        raw_event: dict[str, Any],
    ) -> str:
        """
        Normalize operating system names.
        """

        value = cls._get_first(
            raw_event,
            "os",
            "OS",
            "platform",
            "OperatingSystem",
        )

        if value:
            value = str(value).lower().strip()

            aliases = {
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

            return aliases.get(
                value,
                value,
            )

        # Detect Windows from common Windows fields.
        if any(
            key in raw_event
            for key in (
                "EventID",
                "EventId",
                "EventRecordID",
                "ScriptBlockText",
                "Image",
                "CommandLine",
                "ParentImage",
            )
        ):
            return "windows"

        # Detect Linux from common Linux fields.
        if any(
            key in raw_event
            for key in (
                "syslog",
                "syslog_message",
                "journal",
                "facility",
                "priority",
            )
        ):
            return "linux"

        return "unknown"

    # =========================================================
    # Event type
    # =========================================================

    @classmethod
    def _normalize_event_type(
        cls,
        raw_event: dict[str, Any],
    ) -> str:
        """
        Determine the normalized event type.
        """

        explicit_type = cls._get_first(
            raw_event,
            "event_type",
            "eventType",
            "event.type",
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
                "ScriptBlock",
            )
        ):
            return "powershell_script"

        # -----------------------------------------------------
        # Network
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
                "SourceIP",
                "DestinationIP",
            )
        ):
            return "network_connection"

        # -----------------------------------------------------
        # Registry
        # -----------------------------------------------------

        if any(
            key in raw_event
            for key in (
                "registry_key",
                "RegistryKey",
                "TargetObject",
                "RegistryValueName",
            )
        ):
            return "registry_event"

        # -----------------------------------------------------
        # Process creation
        # -----------------------------------------------------

        event_id = cls._get_first(
            raw_event,
            "EventID",
            "EventId",
        )

        if str(event_id) == "1":
            return "process_creation"

        if any(
            key in raw_event
            for key in (
                "Image",
                "CommandLine",
                "ParentImage",
            )
        ):
            return "process_creation"

        # -----------------------------------------------------
        # File event
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
    # Log source
    # =========================================================

    @classmethod
    def _normalize_log_source(
        cls,
        raw_event: dict[str, Any],
    ) -> str:
        """
        Determine the normalized telemetry source.
        """

        source = cls._get_first(
            raw_event,
            "log_source",
            "logsource",
            "source",
        )

        if source:
            return str(source).lower()

        # Wazuh
        if (
            "rule" in raw_event
            and (
                "agent" in raw_event
                or "manager" in raw_event
            )
        ):
            return "wazuh"

        # Sysmon
        channel = str(
            raw_event.get(
                "Channel",
                "",
            )
        ).lower()

        provider = str(
            raw_event.get(
                "ProviderName",
                "",
            )
        ).lower()

        if "sysmon" in channel:
            return "sysmon"

        if "sysmon" in provider:
            return "sysmon"

        # Windows Event Log
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
    print("BlueSentinel Log Normalizer")
    print("-" * 32)