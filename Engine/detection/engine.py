from typing import Any

from .evaluator import SigmaEvaluator
from .models import SecurityEvent, DetectionResult
from .rule_loader import SigmaRuleLoader


class DetectionEngine:
    """
    Coordinates Sigma rule loading and event evaluation.

    The DetectionEngine receives a security event,
    determines which Sigma rules are applicable to
    that event, evaluates those rules, and returns
    the detections that matched.
    """

    def __init__(
        self,
        rule_loader: SigmaRuleLoader | None = None,
    ):
        self.rule_loader = rule_loader or SigmaRuleLoader()

        self.rules: list[dict[str, Any]] = []

        self.load_rules()

    # =========================================================
    # Rule management
    # =========================================================

    def load_rules(self) -> None:
        """
        Load all community and custom Sigma rules.
        """

        self.rules = self.rule_loader.load_all_rules()

    def reload_rules(self) -> None:
        """
        Reload Sigma rules from disk.
        """

        self.load_rules()

    def get_rule_count(self) -> int:
        """
        Return the number of loaded Sigma rules.
        """

        return len(self.rules)

    # =========================================================
    # Event detection
    # =========================================================

    def detect(
        self,
        event: SecurityEvent | dict[str, Any],
    ) -> list[DetectionResult]:
        """
        Evaluate one security event against applicable
        Sigma rules.

        Only matched detections are returned.
        """

        detections: list[DetectionResult] = []

        event_data = self._event_to_dict(event)

        for rule in self.rules:

            # -------------------------------------------------
            # Skip rules that belong to another telemetry type.
            # -------------------------------------------------

            if not self._is_rule_applicable(
                rule,
                event_data,
            ):
                continue

            evaluator = SigmaEvaluator(rule)

            result = evaluator.evaluate(event)

            if result.matched:
                detections.append(result)

        return detections

    # =========================================================
    # Event conversion
    # =========================================================

    @staticmethod
    def _event_to_dict(
        event: SecurityEvent | dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a SecurityEvent into a dictionary.
        """

        if isinstance(event, SecurityEvent):
            return event.model_dump()

        if isinstance(event, dict):
            return event

        raise TypeError(
            "Event must be a SecurityEvent or dictionary."
        )

    # =========================================================
    # Rule applicability
    # =========================================================

    @classmethod
    def _is_rule_applicable(
        cls,
        rule: dict[str, Any],
        event: dict[str, Any],
    ) -> bool:
        """
        Determine whether a Sigma rule is applicable
        to the supplied security event.

        Sigma rules describe their expected telemetry
        through the logsource section.

        Example:

            logsource:
                product: zeek
                service: rdp

        should not be evaluated against:

            os: windows
            log_source: windows
            event_type: powershell_script
        """

        logsource = rule.get("logsource")

        # -----------------------------------------------------
        # Rules without logsource information are allowed.
        #
        # We cannot safely filter them at this stage.
        # -----------------------------------------------------

        if not isinstance(logsource, dict):
            return True

        # -----------------------------------------------------
        # Check product
        # -----------------------------------------------------

        product = logsource.get("product")

        if product:
            if not cls._product_matches(
                str(product),
                event,
            ):
                return False

        # -----------------------------------------------------
        # Check category
        # -----------------------------------------------------

        category = logsource.get("category")

        if category:
            if not cls._category_matches(
                str(category),
                event,
            ):
                return False

        # -----------------------------------------------------
        # Check service
        # -----------------------------------------------------

        service = logsource.get("service")

        if service:
            if not cls._service_matches(
                str(service),
                event,
            ):
                return False

        return True

    # =========================================================
    # Product matching
    # =========================================================

    @staticmethod
    def _product_matches(
        product: str,
        event: dict[str, Any],
    ) -> bool:
        """
        Compare Sigma logsource product with the
        event's operating system / log source.

        Examples:

            Sigma product: windows
            Event os: windows
                -> applicable

            Sigma product: zeek
            Event log_source: windows
                -> not applicable
        """

        product = product.lower().strip()

        event_os = str(
            event.get("os", "")
        ).lower().strip()

        log_source = str(
            event.get("log_source", "")
        ).lower().strip()

        # -----------------------------------------------------
        # Match against operating system.
        # -----------------------------------------------------

        if event_os == product:
            return True

        # -----------------------------------------------------
        # Match against telemetry source.
        # -----------------------------------------------------

        if log_source == product:
            return True

        # -----------------------------------------------------
        # Common aliases.
        # -----------------------------------------------------

        aliases = {
            "win": "windows",
            "windows": "windows",
            "linux": "linux",
            "unix": "linux",
            "macos": "macos",
            "osx": "macos",
        }

        normalized_product = aliases.get(
            product,
            product,
        )

        normalized_os = aliases.get(
            event_os,
            event_os,
        )

        normalized_source = aliases.get(
            log_source,
            log_source,
        )

        if normalized_product == normalized_os:
            return True

        if normalized_product == normalized_source:
            return True

        return False

    # =========================================================
    # Category matching
    # =========================================================

    @staticmethod
    def _category_matches(
        category: str,
        event: dict[str, Any],
    ) -> bool:
        """
        Compare Sigma logsource category with the
        normalized BlueSentinel event type.
        """

        category = category.lower().strip()

        event_type = str(
            event.get("event_type", "")
        ).lower().strip()

        # -----------------------------------------------------
        # Direct match
        # -----------------------------------------------------

        if category == event_type:
            return True

        # -----------------------------------------------------
        # Known Sigma category mappings.
        #
        # These mappings connect Sigma terminology
        # with BlueSentinel's normalized event types.
        # -----------------------------------------------------

        category_aliases = {
            "ps_script": {
                "powershell_script",
                "ps_script",
                "powershell",
            },
            "ps_module": {
                "powershell_module",
                "ps_module",
            },
            "process_creation": {
                "process_creation",
                "process_start",
            },
            "file_event": {
                "file_event",
                "file_creation",
                "file_modification",
            },
            "registry_event": {
                "registry_event",
                "registry_creation",
                "registry_modification",
            },
            "network_connection": {
                "network_connection",
                "network",
            },
            "dns": {
                "dns",
                "dns_query",
            },
            "firewall": {
                "firewall",
            },
            "proxy": {
                "proxy",
            },
            "webserver": {
                "webserver",
                "web_server",
            },
        }

        allowed_event_types = category_aliases.get(
            category
        )

        # -----------------------------------------------------
        # Unknown category.
        #
        # We cannot safely assume it matches.
        # -----------------------------------------------------

        if allowed_event_types is None:
            return False

        return event_type in allowed_event_types

    # =========================================================
    # Service matching
    # =========================================================

    @staticmethod
    def _service_matches(
        service: str,
        event: dict[str, Any],
    ) -> bool:
        """
        Compare Sigma logsource service with the
        normalized event type or service information.
        """

        service = service.lower().strip()

        event_type = str(
            event.get("event_type", "")
        ).lower().strip()

        event_service = str(
            event.get("service", "")
        ).lower().strip()

        # -----------------------------------------------------
        # Direct service match
        # -----------------------------------------------------

        if event_service == service:
            return True

        # -----------------------------------------------------
        # Event type may contain the service.
        #
        # Example:
        #
        # rdp
        # rdp_connection
        # zeek_rdp
        # -----------------------------------------------------

        if event_type == service:
            return True

        if event_type.startswith(
            f"{service}_"
        ):
            return True

        if event_type.endswith(
            f"_{service}"
        ):
            return True

        return False


if __name__ == "__main__":
    print("BlueSentinel Detection Engine")
    print("-" * 35)

    engine = DetectionEngine()

    print(
        f"Loaded Sigma rules: "
        f"{engine.get_rule_count()}"
    )