"""
APIGhost Reporter

Generates scan reports in various formats: JSON, HTML, Markdown, and SARIF.
"""

import json
import os
from typing import Any
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from apighost.models import ChainResult
from apighost import __version__

# Default paths
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class Reporter:
    """Generates scan reports in various formats."""

    def __init__(self, results: list[ChainResult]):
        self.results = results
        self.timestamp = datetime.now().isoformat()
        
        # Summary statistics
        self.total = len(results)
        self.confirmed = sum(1 for r in results if r.verdict.value == "CONFIRMED")
        self.likely = sum(1 for r in results if r.verdict.value == "LIKELY")
        self.possible = sum(1 for r in results if r.verdict.value == "POSSIBLE")
        self.secure = sum(1 for r in results if r.verdict.value == "SECURE")
        self.errors = sum(1 for r in results if r.verdict.value == "ERROR")
        
        # Ensure template dir exists
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        self._create_default_templates()
        
        self.env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

    def _create_default_templates(self) -> None:
        """Create default Jinja2 templates if they don't exist."""
        html_path = os.path.join(TEMPLATE_DIR, "report.html.j2")
        md_path = os.path.join(TEMPLATE_DIR, "report.md.j2")
        
        if not os.path.exists(html_path):
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self._default_html_template())
                
        if not os.path.exists(md_path):
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self._default_md_template())

    def _default_html_template(self) -> str:
        html_path = os.path.join(TEMPLATE_DIR, "report.html.j2")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                return f.read()
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APIGhost Scan Report</title>
</head>
<body>
    <span class="verdict-CONFIRMED"></span>
</body>
</html>"""

    def _default_md_template(self) -> str:
        return """# APIGhost Scan Report

**Generated:** {{ timestamp }}  
**Version:** APIGhost v{{ version }}

## Summary
- **Total Chains Scanned:** {{ total }}
- **Confirmed BOLA:** {{ confirmed }} 🔴
- **Likely BOLA:** {{ likely }} 🟠
- **Possible:** {{ possible }} 🟡
- **Secure:** {{ secure }} 🟢
- **Errors:** {{ errors }} ⚪

### Verdict Distribution

```mermaid
pie title Verdict Distribution
    "Confirmed BOLA" : {{ confirmed }}
    "Likely BOLA" : {{ likely }}
    "Possible" : {{ possible }}
    "Secure" : {{ secure }}
    "Errors" : {{ errors }}
```

### Verdict Count Breakdown

```mermaid
xychart-beta
    title "Results by Verdict Category"
    x-axis ["Confirmed", "Likely", "Possible", "Secure", "Errors"]
    y-axis "Count" 0 --> {{ total }}
    bar [{{ confirmed }}, {{ likely }}, {{ possible }}, {{ secure }}, {{ errors }}]
```

### Scan Execution Flow

```mermaid
flowchart LR
    A["📄 Spec Parsed"] --> B["🔗 {{ total }} Chains Built"]
    B --> C["⚔️ Cross-User Tests"]
    C --> D["🔴 {{ confirmed }} Confirmed"]
    C --> E["🟠 {{ likely }} Likely"]
    C --> F["🟡 {{ possible }} Possible"]
    C --> G["🟢 {{ secure }} Secure"]
    C --> H["⚪ {{ errors }} Errors"]
```

{% if results %}
### Per-Chain Score Distribution

```mermaid
xychart-beta
    title "BOLA Score per Attack Chain"
    x-axis [{% for result in results %}"{{ result.chain.chain_id }}"{% if not loop.last %}, {% endif %}{% endfor %}]
    y-axis "Score" 0 --> 1
    bar [{% for result in results %}{{ "%.2f"|format(result.score) }}{% if not loop.last %}, {% endif %}{% endfor %}]
```
{% endif %}

## Detailed Results

| Chain ID | Resource | Variant | Verdict | Score | Attack Endpoint |
|----------|----------|---------|---------|-------|-----------------|
{% for result in results -%}
| {{ result.chain.chain_id }} | {{ result.chain.resource_name }} | {{ result.chain.variant.value }} | **{{ result.verdict.value }}** | {{ "%.2f"|format(result.score) }} | `{{ result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value }} {{ result.chain.attack.path if result.chain.attack else result.chain.read.path }}` |
{% endfor %}
"""

    def get_template_data(self) -> dict[str, Any]:
        """Get the data dictionary used for Jinja templates."""
        return {
            "version": __version__,
            "timestamp": self.timestamp,
            "total": self.total,
            "confirmed": self.confirmed,
            "likely": self.likely,
            "possible": self.possible,
            "secure": self.secure,
            "errors": self.errors,
            "results": self.results,
            "results_json": self.generate_json(),
        }

    def generate_json(self) -> str:
        """Generate a JSON report."""
        report = {
            "tool": "APIGhost",
            "version": __version__,
            "timestamp": self.timestamp,
            "summary": {
                "total": self.total,
                "confirmed": self.confirmed,
                "likely": self.likely,
                "secure": self.secure,
                "errors": self.errors
            },
            "results": []
        }

        for result in self.results:
            report["results"].append({
                "chain_id": result.chain.chain_id,
                "resource": result.chain.resource_name,
                "variant": result.chain.variant.value,
                "verdict": result.verdict.value,
                "score": round(result.score, 4),
                "signals": {k: round(v, 4) for k, v in result.signals.items()},
                "attack_endpoint": f"{result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value} {result.chain.attack.path if result.chain.attack else result.chain.read.path}",
                "create_status": result.create_status,
                "resource_ids": result.resource_ids,
                "read_as_owner_status": result.read_as_owner_status,
                "read_as_attacker_status": result.read_as_attacker_status,
                "teardown_success": result.teardown_success,
                "duration_ms": result.duration_ms,
                "error": result.error,
            })
            
        return json.dumps(report, indent=2)

    def generate_html(self) -> str:
        """Generate an HTML report using Jinja2."""
        template = self.env.get_template("report.html.j2")
        return template.render(**self.get_template_data())

    def generate_markdown(self) -> str:
        """Generate a Markdown report using Jinja2."""
        template = self.env.get_template("report.md.j2")
        return template.render(**self.get_template_data())

    def generate_sarif(self) -> str:
        """Generate a SARIF (Static Analysis Results Interchange Format) report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "APIGhost",
                        "informationUri": "https://github.com/Arul-AGC/APIGhost",
                        "version": __version__,
                        "rules": [
                            {
                                "id": "API1-BOLA",
                                "name": "Broken Object Level Authorization",
                                "shortDescription": {"text": "A user can access or modify an object they do not own."}
                            }
                        ]
                    }
                },
                "results": []
            }]
        }
        
        for result in self.results:
            if result.verdict.value in ("CONFIRMED", "LIKELY"):
                level = "error" if result.verdict.value == "CONFIRMED" else "warning"
                attack_str = f"{result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value} {result.chain.attack.path if result.chain.attack else result.chain.read.path}"
                
                sarif_result = {
                    "ruleId": "API1-BOLA",
                    "level": level,
                    "message": {
                        "text": f"BOLA ({result.chain.variant.value}) detected on {attack_str}. Attacker received HTTP {result.read_as_attacker_status} (Score: {result.score:.2f})."
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": attack_str.split(" ")[1]
                            }
                        }
                    }]
                }
                sarif["runs"][0]["results"].append(sarif_result)
                
        return json.dumps(sarif, indent=2)
        
    def save(self, filepath: str, format: str = "json") -> None:
        """Generate and save the report to the specified file."""
        format = format.lower()
        if format == "html":
            content = self.generate_html()
        elif format == "md" or format == "markdown":
            content = self.generate_markdown()
        elif format == "sarif":
            content = self.generate_sarif()
        else:
            content = self.generate_json()
            
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
