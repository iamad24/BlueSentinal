from pathlib import Path
from typing import Any

import yaml


class SigmaRuleLoader:
    """
    Loads Sigma YAML rules from the cloned Sigma repository
    and from BlueSentinel's custom rule directory.
    """

    def __init__(
        self,
        sigma_repository_path: str | Path | None = None,
        custom_rules_path: str | Path | None = None,
    ):
        project_root = Path(__file__).resolve().parents[3]

        if sigma_repository_path is None:
            sigma_repository_path = (
                project_root / "Sigma_rules" / "sigma" / "rules"
            )

        if custom_rules_path is None:
            custom_rules_path = (
                project_root / "XDR" / "sigma_rules" / "custom"
            )

        self.sigma_repository_path = Path(sigma_repository_path)
        self.custom_rules_path = Path(custom_rules_path)

    def _load_yaml_file(self, file_path: Path) -> dict[str, Any] | None:
        """
        Load one YAML file and return its contents.
        Invalid or non-dictionary YAML files are skipped.
        """

        try:
            with file_path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)

            if not isinstance(data, dict):
                return None

            return data

        except (OSError, yaml.YAMLError):
            return None

    def _find_rule_files(self, directory: Path) -> list[Path]:
        """
        Find all YAML Sigma rule files inside a directory.
        """

        if not directory.exists():
            return []

        if not directory.is_dir():
            return []

        rule_files = []

        for pattern in ("*.yml", "*.yaml"):
            rule_files.extend(directory.rglob(pattern))

        return sorted(set(rule_files))

    def load_rule(self, file_path: str | Path) -> dict[str, Any] | None:
        """
        Load one Sigma rule from a specific YAML file.
        """

        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return None

        return self._load_yaml_file(path)

    def load_rules_from_directory(
        self,
        directory: str | Path,
    ) -> list[dict[str, Any]]:
        """
        Load all valid YAML rules from a directory.
        """

        directory = Path(directory)

        rules = []

        for file_path in self._find_rule_files(directory):
            rule = self._load_yaml_file(file_path)

            if rule is not None:
                rule["_file_path"] = str(file_path)
                rules.append(rule)

        return rules

    def load_community_rules(self) -> list[dict[str, Any]]:
        """
        Load Sigma rules from the cloned SigmaHQ repository.
        """

        return self.load_rules_from_directory(
            self.sigma_repository_path
        )

    def load_custom_rules(self) -> list[dict[str, Any]]:
        """
        Load BlueSentinel's custom Sigma rules.
        """

        return self.load_rules_from_directory(
            self.custom_rules_path
        )

    def load_all_rules(self) -> list[dict[str, Any]]:
        """
        Load both community and BlueSentinel custom rules.
        """

        community_rules = self.load_community_rules()
        custom_rules = self.load_custom_rules()

        return community_rules + custom_rules

    def get_rule_count(self) -> dict[str, int]:
        """
        Return the number of community and custom rules available.
        """

        community_rules = self.load_community_rules()
        custom_rules = self.load_custom_rules()

        return {
            "community_rules": len(community_rules),
            "custom_rules": len(custom_rules),
            "total_rules": len(community_rules) + len(custom_rules),
        }


if __name__ == "__main__":
    loader = SigmaRuleLoader()

    counts = loader.get_rule_count()

    print("BlueSentinel Sigma Rule Loader")
    print("-" * 35)
    print(f"Community rules : {counts['community_rules']}")
    print(f"Custom rules    : {counts['custom_rules']}")
    print(f"Total rules     : {counts['total_rules']}")