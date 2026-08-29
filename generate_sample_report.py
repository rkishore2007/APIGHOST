"""
Generate a sample APIGhost HTML report with realistic mock scan data.
This produces a report with mixed verdicts so you can see the graphs populated.
"""

import sys
import os
import random

# Fix Windows console encoding for emoji output
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add the src directory to path so we can import apighost
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from apighost.models import (
    Endpoint, HttpMethod, AttackChain, ChainResult,
    ChainSource, ChainVariant, Verdict,
)
from apighost.reporter import Reporter


def make_endpoint(method: HttpMethod, path: str, has_params: bool = False) -> Endpoint:
    param_names = []
    if has_params:
        import re
        param_names = re.findall(r'\{(\w+)\}', path)
    return Endpoint(
        path=path,
        method=method,
        has_path_params=has_params,
        path_param_names=param_names,
    )


# ── Define realistic API endpoints ──
CHAINS_DATA = [
    # (chain_id, resource, variant, create_path, read_path, delete_path, attack_path, attack_method, verdict, score)
    ("CHAIN_001", "orders", ChainVariant.READ, "/api/orders", "/api/orders/{id}", "/api/orders/{id}", None, None,
     Verdict.CONFIRMED, 0.92),
    ("CHAIN_002", "users", ChainVariant.READ, "/api/users", "/api/users/{user_id}", None, None, None,
     Verdict.CONFIRMED, 0.87),
    ("CHAIN_003", "invoices", ChainVariant.READ, "/api/invoices", "/api/invoices/{id}", "/api/invoices/{id}", None, None,
     Verdict.LIKELY, 0.68),
    ("CHAIN_004", "payments", ChainVariant.READ, "/api/payments", "/api/payments/{id}", None, None, None,
     Verdict.LIKELY, 0.55),
    ("CHAIN_005", "orders", ChainVariant.UPDATE, "/api/orders", "/api/orders/{id}", "/api/orders/{id}",
     "/api/orders/{id}", HttpMethod.PUT,
     Verdict.CONFIRMED, 0.95),
    ("CHAIN_006", "users", ChainVariant.UPDATE, "/api/users", "/api/users/{user_id}", None,
     "/api/users/{user_id}", HttpMethod.PATCH,
     Verdict.LIKELY, 0.61),
    ("CHAIN_007", "products", ChainVariant.READ, "/api/products", "/api/products/{id}", "/api/products/{id}", None, None,
     Verdict.SECURE, 0.08),
    ("CHAIN_008", "categories", ChainVariant.READ, "/api/categories", "/api/categories/{id}", None, None, None,
     Verdict.SECURE, 0.05),
    ("CHAIN_009", "reviews", ChainVariant.READ, "/api/reviews", "/api/reviews/{id}", "/api/reviews/{id}", None, None,
     Verdict.POSSIBLE, 0.35),
    ("CHAIN_010", "comments", ChainVariant.READ, "/api/comments", "/api/comments/{id}", None, None, None,
     Verdict.POSSIBLE, 0.28),
    ("CHAIN_011", "orders", ChainVariant.DELETE, "/api/orders", "/api/orders/{id}", "/api/orders/{id}",
     "/api/orders/{id}", HttpMethod.DELETE,
     Verdict.CONFIRMED, 0.89),
    ("CHAIN_012", "coupons", ChainVariant.READ, "/api/coupons", "/api/coupons/{code}", None, None, None,
     Verdict.SECURE, 0.12),
    ("CHAIN_013", "addresses", ChainVariant.READ, "/api/addresses", "/api/addresses/{id}", "/api/addresses/{id}", None, None,
     Verdict.LIKELY, 0.72),
    ("CHAIN_014", "notifications", ChainVariant.READ, "/api/notifications", "/api/notifications/{id}", None, None, None,
     Verdict.SECURE, 0.03),
    ("CHAIN_015", "wishlist", ChainVariant.READ, "/api/wishlist", "/api/wishlist/{id}", None, None, None,
     Verdict.POSSIBLE, 0.41),
    ("CHAIN_016", "admin-panel", ChainVariant.BFLA, "/api/admin/users", "/api/admin/users/{id}", None,
     "/api/admin/users/{id}", HttpMethod.GET,
     Verdict.CONFIRMED, 0.98),
    ("CHAIN_017", "users", ChainVariant.MASS_ASSIGNMENT, "/api/users", "/api/users/{user_id}", None,
     "/api/users/{user_id}", HttpMethod.PUT,
     Verdict.LIKELY, 0.58),
    ("CHAIN_018", "cart", ChainVariant.READ, "/api/cart", "/api/cart/{id}", None, None, None,
     Verdict.SECURE, 0.10),
]


def build_mock_results() -> list[ChainResult]:
    results = []
    for (chain_id, resource, variant, create_path, read_path, delete_path,
         attack_path, attack_method, verdict, score) in CHAINS_DATA:

        create_ep = make_endpoint(HttpMethod.POST, create_path)
        read_ep = make_endpoint(HttpMethod.GET, read_path, has_params=True)
        delete_ep = make_endpoint(HttpMethod.DELETE, delete_path, has_params=True) if delete_path else None
        attack_ep = make_endpoint(attack_method, attack_path, has_params=True) if attack_path and attack_method else None

        chain = AttackChain(
            chain_id=chain_id,
            resource_name=resource,
            source=ChainSource.LAYER1_PATH,
            create=create_ep,
            read=read_ep,
            delete=delete_ep,
            attack=attack_ep,
            id_fields=["id"],
            variant=variant,
            confidence=random.uniform(0.75, 1.0),
        )

        # Generate realistic HTTP statuses based on verdict
        if verdict == Verdict.CONFIRMED:
            owner_status, attacker_status = 200, 200
        elif verdict == Verdict.LIKELY:
            owner_status, attacker_status = 200, 200
        elif verdict == Verdict.POSSIBLE:
            owner_status, attacker_status = 200, random.choice([200, 403])
        else:  # SECURE
            owner_status, attacker_status = 200, random.choice([403, 404])

        # Generate realistic heuristic signals
        signals = {
            "status_code": round(random.uniform(0.0, 1.0) * score + 0.05, 4),
            "structural_similarity": round(random.uniform(0.6, 1.0) * score, 4),
            "data_leakage": round(random.uniform(0.3, 1.0) * score, 4),
            "content_length": round(random.uniform(0.4, 0.9) * score, 4),
            "error_keywords": round(max(0, 1.0 - score - random.uniform(0, 0.2)), 4),
        }

        result = ChainResult(
            chain=chain,
            verdict=verdict,
            score=score,
            create_status=201,
            create_body={"id": f"res_{random.randint(1000, 9999)}"},
            resource_ids={"id": f"res_{random.randint(1000, 9999)}"},
            read_as_owner_status=owner_status,
            read_as_owner_body={"id": "res_1234", "name": "Sample", "email": "owner@test.com"},
            read_as_attacker_status=attacker_status,
            read_as_attacker_body=(
                {"id": "res_1234", "name": "Sample", "email": "owner@test.com"}
                if verdict in (Verdict.CONFIRMED, Verdict.LIKELY)
                else {"error": "Forbidden"}
            ),
            teardown_success=delete_path is not None,
            signals=signals,
            duration_ms=random.randint(80, 950),
        )
        results.append(result)

    return results


if __name__ == "__main__":
    print("🔧 Generating sample APIGhost report with mock vulnerability data...")
    results = build_mock_results()

    reporter = Reporter(results)

    # Generate HTML reports (both primary report.html and secondary sample_report.html)
    sample_html_path = os.path.join(os.path.dirname(__file__), "sample_report.html")
    primary_html_path = os.path.join(os.path.dirname(__file__), "report.html")
    reporter.save(sample_html_path, format="html")
    reporter.save(primary_html_path, format="html")
    print(f"  ✅ HTML sample report saved:  {sample_html_path}")
    print(f"  ✅ HTML primary report saved: {primary_html_path}")

    # Generate Markdown reports
    sample_md_path = os.path.join(os.path.dirname(__file__), "sample_report.md")
    primary_md_path = os.path.join(os.path.dirname(__file__), "report.md")
    reporter.save(sample_md_path, format="md")
    reporter.save(primary_md_path, format="md")
    print(f"  ✅ Markdown reports saved:    {sample_md_path} & {primary_md_path}")

    # Generate JSON reports
    sample_json_path = os.path.join(os.path.dirname(__file__), "sample_report.json")
    primary_json_path = os.path.join(os.path.dirname(__file__), "report.json")
    reporter.save(sample_json_path, format="json")
    reporter.save(primary_json_path, format="json")
    print(f"  ✅ JSON reports saved:        {sample_json_path} & {primary_json_path}")

    # Print summary
    print(f"\n📊 Sample Data Summary:")
    print(f"  Total Chains:  {reporter.total}")
    print(f"  🔴 Confirmed:  {reporter.confirmed}")
    print(f"  🟠 Likely:     {reporter.likely}")
    print(f"  🟡 Possible:   {reporter.possible}")
    print(f"  🟢 Secure:     {reporter.secure}")
    print(f"  ⚪ Errors:     {reporter.errors}")

    print(f"\n🌐 Opening sample_report.html in your browser...")
    try:
        os.startfile(sample_html_path)
    except Exception:
        import webbrowser
        webbrowser.open(sample_html_path)

