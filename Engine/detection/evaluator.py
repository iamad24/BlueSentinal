import re
from typing import Any

from .models import SecurityEvent, DetectionResult


class SigmaEvaluator:
    """
    Evaluates a normalized BlueSentinel SecurityEvent
    against a Sigma rule.
    """

    def __init__(self, rule: dict[str, Any]):
        self.rule = rule

    # =========================================================
    # Main evaluation
    # =========================================================

    def evaluate(
        self,
        event: SecurityEvent | dict[str, Any],
    ) -> DetectionResult:
        """
        Evaluate one security event against one Sigma rule.
        """

        event_data = self._event_to_dict(event)

        detection = self.rule.get("detection", {})

        if not isinstance(detection, dict) or not detection:
            return DetectionResult(
                matched=False,
                rule_id=self.rule.get("id"),
                rule_title=self.rule.get("title"),
                severity=self._get_severity(),
                description=self.rule.get("description"),
            )

        condition = detection.get("condition")

        if not condition:
            return DetectionResult(
                matched=False,
                rule_id=self.rule.get("id"),
                rule_title=self.rule.get("title"),
                severity=self._get_severity(),
                description=self.rule.get("description"),
            )

        try:
            matched = self._evaluate_condition(
                str(condition),
                detection,
                event_data,
            )

        except (
            TypeError,
            ValueError,
            KeyError,
            re.error,
        ):
            matched = False

        return DetectionResult(
            matched=matched,
            rule_id=self.rule.get("id"),
            rule_title=self.rule.get("title"),
            severity=self._get_severity(),
            description=self.rule.get("description"),
            mitre_techniques=self._get_mitre_techniques(),
            evidence=self._build_evidence(
                event_data,
                matched,
            ),
        )

    # =========================================================
    # Event handling
    # =========================================================

    @staticmethod
    def _event_to_dict(
        event: SecurityEvent | dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a SecurityEvent/Pydantic model into a dictionary.
        """

        if isinstance(event, SecurityEvent):
            return event.model_dump()

        if isinstance(event, dict):
            return event

        raise TypeError(
            "Event must be a SecurityEvent or dictionary."
        )

    # =========================================================
    # Condition handling
    # =========================================================

    def _evaluate_condition(
        self,
        condition: str,
        detection: dict[str, Any],
        event: dict[str, Any],
    ) -> bool:
        """
        Evaluate common Sigma condition forms.

        Supported examples:

            selection
            selection and filter
            selection or filter
            1 of selection*
            all of selection*
            1 of them
            all of them
        """

        condition = condition.strip()

        # Remove simple outer parentheses.
        while (
            condition.startswith("(")
            and condition.endswith(")")
        ):
            condition = condition[1:-1].strip()

        # -----------------------------------------------------
        # OR
        # -----------------------------------------------------

        or_parts = self._split_condition(
            condition,
            "or",
        )

        if len(or_parts) > 1:
            return any(
                self._evaluate_condition(
                    part,
                    detection,
                    event,
                )
                for part in or_parts
            )

        # -----------------------------------------------------
        # AND
        # -----------------------------------------------------

        and_parts = self._split_condition(
            condition,
            "and",
        )

        if len(and_parts) > 1:
            return all(
                self._evaluate_condition(
                    part,
                    detection,
                    event,
                )
                for part in and_parts
            )

        # -----------------------------------------------------
        # "1 of selection*"
        # -----------------------------------------------------

        match = re.fullmatch(
            r"(\d+)\s+of\s+([A-Za-z0-9_*]+)",
            condition,
            flags=re.IGNORECASE,
        )

        if match:
            number = int(match.group(1))
            pattern = match.group(2)

            names = self._matching_selection_names(
                detection,
                pattern,
            )

            if not names:
                return False

            matches = sum(
                self._evaluate_selection(
                    detection[name],
                    event,
                )
                for name in names
            )

            return matches >= number

        # -----------------------------------------------------
        # "all of selection*"
        # -----------------------------------------------------

        match = re.fullmatch(
            r"all\s+of\s+([A-Za-z0-9_*]+)",
            condition,
            flags=re.IGNORECASE,
        )

        if match:
            pattern = match.group(1)

            names = self._matching_selection_names(
                detection,
                pattern,
            )

            if not names:
                return False

            return all(
                self._evaluate_selection(
                    detection[name],
                    event,
                )
                for name in names
            )

        # -----------------------------------------------------
        # "1 of them"
        # -----------------------------------------------------

        match = re.fullmatch(
            r"(\d+)\s+of\s+them",
            condition,
            flags=re.IGNORECASE,
        )

        if match:
            number = int(match.group(1))

            names = [
                name
                for name in detection
                if name != "condition"
            ]

            matches = sum(
                self._evaluate_selection(
                    detection[name],
                    event,
                )
                for name in names
            )

            return matches >= number

        # -----------------------------------------------------
        # "all of them"
        # -----------------------------------------------------

        if re.fullmatch(
            r"all\s+of\s+them",
            condition,
            flags=re.IGNORECASE,
        ):
            names = [
                name
                for name in detection
                if name != "condition"
            ]

            if not names:
                return False

            return all(
                self._evaluate_selection(
                    detection[name],
                    event,
                )
                for name in names
            )

        # -----------------------------------------------------
        # Direct selection name
        # -----------------------------------------------------

        if condition in detection:
            return self._evaluate_selection(
                detection[condition],
                event,
            )

        return False

    # =========================================================
    # Condition splitting
    # =========================================================

    @staticmethod
    def _split_condition(
        condition: str,
        operator: str,
    ) -> list[str]:
        """
        Split a Sigma condition while avoiding
        simple nested parentheses.
        """

        parts: list[str] = []
        current: list[str] = []
        depth = 0

        tokens = condition.split()

        for token in tokens:

            depth += token.count("(")
            depth -= token.count(")")

            if (
                token.lower() == operator.lower()
                and depth == 0
            ):
                parts.append(
                    " ".join(current).strip()
                )

                current = []

            else:
                current.append(token)

        if current:
            parts.append(
                " ".join(current).strip()
            )

        return [
            part
            for part in parts
            if part
        ]

    # =========================================================
    # Selection names
    # =========================================================

    @staticmethod
    def _matching_selection_names(
        detection: dict[str, Any],
        pattern: str,
    ) -> list[str]:
        """
        Return detection selection names matching
        a wildcard pattern.
        """

        regex_pattern = (
            "^"
            + re.escape(pattern).replace(
                r"\*",
                ".*",
            )
            + "$"
        )

        regex = re.compile(
            regex_pattern,
            flags=re.IGNORECASE,
        )

        return [
            name
            for name in detection
            if (
                name != "condition"
                and regex.match(name)
            )
        ]

    # =========================================================
    # Selection handling
    # =========================================================

    def _evaluate_selection(
        self,
        selection: Any,
        event: dict[str, Any],
    ) -> bool:
        """
        Evaluate one Sigma detection selection.

        A selection dictionary means all fields
        inside that selection must match.
        """

        if not isinstance(selection, dict):
            return False

        for field, expected_value in selection.items():

            # -------------------------------------------------
            # Sigma field syntax:
            #
            # ScriptBlockText|contains
            # CommandLine|startswith
            # Image|endswith
            # -------------------------------------------------

            field_parts = str(field).split("|")

            field_name = field_parts[0]

            modifiers = [
                modifier.lower()
                for modifier in field_parts[1:]
            ]

            actual_value = self._get_event_field(
                event,
                field_name,
            )

            # -------------------------------------------------
            # Sigma value can be a list.
            #
            # Any value in the list can match.
            # -------------------------------------------------

            if isinstance(expected_value, list):

                if not any(
                    self._match_value(
                        actual_value,
                        value,
                        modifiers,
                    )
                    for value in expected_value
                ):
                    return False

            else:

                if not self._match_value(
                    actual_value,
                    expected_value,
                    modifiers,
                ):
                    return False

        return True

    # =========================================================
    # Event field handling
    # =========================================================

    @staticmethod
    def _get_event_field(
        event: dict[str, Any],
        field: str,
    ) -> Any:
        """
        Retrieve a field from the normalized event.

        Lookup order:

        1. Direct event field
        2. Sigma -> BlueSentinel field alias
        3. Nested event field
        4. raw_event direct field
        5. raw_event nested field
        """

        # -----------------------------------------------------
        # Direct field
        # -----------------------------------------------------

        if field in event:
            return event[field]

        # -----------------------------------------------------
        # Sigma -> BlueSentinel aliases
        # -----------------------------------------------------

        field_aliases = {
            "Image": "process",
            "ParentImage": "parent_process",
            "CommandLine": "command_line",
            "User": "user",
            "SourceIp": "source_ip",
            "DestinationIp": "destination_ip",
            "SourcePort": "source_port",
            "DestinationPort": "destination_port",
            "FileName": "file_path",
            "TargetFilename": "file_path",
            "Hashes": "file_hash",
        }

        normalized_field = field_aliases.get(
            field,
            field,
        )

        # -----------------------------------------------------
        # Normalized field
        # -----------------------------------------------------

        if normalized_field in event:
            return event[normalized_field]

        # -----------------------------------------------------
        # Nested field in normalized event
        #
        # Example:
        # process.command_line
        # -----------------------------------------------------

        current: Any = event

        for part in normalized_field.split("."):

            if not isinstance(current, dict):
                current = None
                break

            current = current.get(part)

            if current is None:
                break

        if current is not None:
            return current

        # -----------------------------------------------------
        # raw_event
        # -----------------------------------------------------

        raw_event = event.get("raw_event")

        if not isinstance(raw_event, dict):
            return None

        # Direct raw_event field
        if field in raw_event:
            return raw_event[field]

        # Normalized field inside raw_event
        if normalized_field in raw_event:
            return raw_event[normalized_field]

        # Nested raw_event field
        current = raw_event

        for part in normalized_field.split("."):

            if not isinstance(current, dict):
                return None

            current = current.get(part)

            if current is None:
                return None

        return current

    # =========================================================
    # Value matching
    # =========================================================

    def _match_value(
        self,
        actual: Any,
        expected: Any,
        modifiers: list[str] | None = None,
    ) -> bool:
        """
        Match an event value against a Sigma value.

        Supports:

            exact
            contains
            startswith
            endswith
            wildcards
            regex
        """

        if modifiers is None:
            modifiers = []

        # -----------------------------------------------------
        # No actual value
        # -----------------------------------------------------

        if actual is None:
            return False

        # -----------------------------------------------------
        # Event value is a list
        # -----------------------------------------------------

        if isinstance(actual, list):

            return any(
                self._match_value(
                    item,
                    expected,
                    modifiers,
                )
                for item in actual
            )

        # -----------------------------------------------------
        # Boolean
        # -----------------------------------------------------

        if isinstance(expected, bool):
            return actual is expected

        actual_string = str(actual)
        expected_string = str(expected)

        # =====================================================
        # Sigma modifiers
        # =====================================================

        if modifiers:

            result = actual_string

            for modifier in modifiers:

                modifier = modifier.lower()

                # ---------------------------------------------
                # contains
                # ---------------------------------------------

                if modifier == "contains":

                    if (
                        expected_string.lower()
                        not in result.lower()
                    ):
                        return False

                # ---------------------------------------------
                # startswith
                # ---------------------------------------------

                elif modifier == "startswith":

                    if not result.lower().startswith(
                        expected_string.lower()
                    ):
                        return False

                # ---------------------------------------------
                # endswith
                # ---------------------------------------------

                elif modifier == "endswith":

                    if not result.lower().endswith(
                        expected_string.lower()
                    ):
                        return False

                # ---------------------------------------------
                # all
                # ---------------------------------------------

                elif modifier == "all":

                    if (
                        expected_string.lower()
                        not in result.lower()
                    ):
                        return False

                # ---------------------------------------------
                # Unknown modifier
                # ---------------------------------------------

                else:
                    return False

            return True

        # =====================================================
        # Sigma regex syntax
        #
        # Example:
        # /powershell.*encodedcommand/
        # =====================================================

        if (
            len(expected_string) >= 2
            and expected_string.startswith("/")
            and expected_string.endswith("/")
        ):

            pattern = expected_string[1:-1]

            return (
                re.search(
                    pattern,
                    actual_string,
                    flags=re.IGNORECASE,
                )
                is not None
            )

        # =====================================================
        # Wildcard matching
        #
        # Example:
        # powershell*
        # *.exe
        # pow?rshell
        # =====================================================

        if (
            "*"
            in expected_string
            or "?"
            in expected_string
        ):

            pattern = re.escape(
                expected_string
            )

            pattern = pattern.replace(
                r"\*",
                ".*",
            ).replace(
                r"\?",
                ".",
            )

            return (
                re.fullmatch(
                    pattern,
                    actual_string,
                    flags=re.IGNORECASE,
                )
                is not None
            )

        # =====================================================
        # Normal exact comparison
        # =====================================================

        return (
            actual_string.lower()
            == expected_string.lower()
        )

    # =========================================================
    # Severity
    # =========================================================

    def _get_severity(self) -> str | None:
        """
        Read severity from Sigma rule metadata.
        """

        level = self.rule.get("level")

        if level:
            return str(level).upper()

        return None

    # =========================================================
    # MITRE ATT&CK
    # =========================================================

    def _get_mitre_techniques(self) -> list[str]:
        """
        Extract MITRE ATT&CK technique IDs
        from Sigma tags.
        """

        tags = self.rule.get(
            "tags",
            [],
        )

        techniques: list[str] = []

        for tag in tags:

            tag_string = str(tag)

            match = re.search(
                r"attack\.(t\d{4}(?:\.\d{3})?)",
                tag_string,
                flags=re.IGNORECASE,
            )

            if match:
                techniques.append(
                    match.group(1).upper()
                )

        return sorted(
            set(techniques)
        )

    # =========================================================
    # Evidence
    # =========================================================

    @staticmethod
    def _build_evidence(
        event: dict[str, Any],
        matched: bool,
    ) -> dict[str, Any]:
        """
        Store useful evidence when a rule matches.
        """

        if not matched:
            return {}

        evidence_fields = [
            "process",
            "parent_process",
            "command_line",
            "user",
            "source_ip",
            "destination_ip",
            "file_path",
            "file_hash",
            "registry_key",
        ]

        evidence: dict[str, Any] = {}

        for field in evidence_fields:

            value = event.get(field)

            if value is not None:
                evidence[field] = value

        # Also include raw event as evidence
        # when available.
        raw_event = event.get("raw_event")

        if isinstance(raw_event, dict):
            evidence["raw_event"] = raw_event

        return evidence