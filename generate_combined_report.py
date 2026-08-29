"""
APIGhost Combined Multi-Dataset Report Generator
Combines both sample_report.html (18 chains) and live scan results (22 chains)
into a unified, interactive multi-report HTML dashboard with tab switching and aggregated analytics.
"""

import sys
import os
import json

# Fix Windows console encoding for emoji output
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def build_live_scan_results():
    """22 Attack chains executed against the live API target."""
    return [
        {"chain_id": "CHAIN_001", "resource": "orders", "variant": "READ", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 101},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 47, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_002", "resource": "orders", "variant": "UPDATE", "verdict": "LIKELY", "score": 0.53,
         "attack_endpoint": "PUT /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 102},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 31, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 0.29, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.52}},
        {"chain_id": "CHAIN_003", "resource": "orders", "variant": "DELETE", "verdict": "SECURE", "score": 0.16,
         "attack_endpoint": "DELETE /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 103},
         "read_as_owner_status": 200, "read_as_attacker_status": 204, "teardown_success": True, "duration_ms": 30, "error": None,
         "signals": {"status_code": 0.2, "structural_similarity": 0.0, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.02}},
        {"chain_id": "CHAIN_004", "resource": "orders", "variant": "MASS_ASSIGNMENT", "verdict": "SECURE", "score": 0.00,
         "attack_endpoint": "PUT /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 104},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 46, "error": None,
         "signals": {"status_code": 0.0, "structural_similarity": 0.0, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.0}},
        {"chain_id": "CHAIN_005", "resource": "users", "variant": "READ", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 501},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 16, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_006", "resource": "users", "variant": "UPDATE", "verdict": "LIKELY", "score": 0.57,
         "attack_endpoint": "PUT /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 502},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 0.40, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.69}},
        {"chain_id": "CHAIN_007", "resource": "users", "variant": "MASS_ASSIGNMENT", "verdict": "SECURE", "score": 0.00,
         "attack_endpoint": "PUT /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 503},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 47, "error": None,
         "signals": {"status_code": 0.0, "structural_similarity": 0.0, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.0}},
        {"chain_id": "CHAIN_008", "resource": "create-review", "variant": "READ", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/fetch-review", "create_status": 200, "resource_ids": {"review_id": 701},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_009", "resource": "orders", "variant": "EXCESSIVE_DATA", "verdict": "SECURE", "score": 0.00,
         "attack_endpoint": "GET /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 105},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 31, "error": None,
         "signals": {"status_code": 0.0, "structural_similarity": 0.0, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.0}},
        {"chain_id": "CHAIN_010", "resource": "users", "variant": "EXCESSIVE_DATA", "verdict": "SECURE", "score": 0.00,
         "attack_endpoint": "GET /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 504},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 31, "error": None,
         "signals": {"status_code": 0.0, "structural_similarity": 0.0, "data_leakage": 0.0, "error_keywords": 1.0, "content_length": 0.0}},
        {"chain_id": "CHAIN_011", "resource": "create-review", "variant": "EXCESSIVE_DATA", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/fetch-review", "create_status": 200, "resource_ids": {"review_id": 702},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 31, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_012", "resource": "orders", "variant": "INJECTION", "verdict": "ERROR", "score": 0.00,
         "attack_endpoint": "POST /api/orders", "create_status": 0, "resource_ids": {},
         "read_as_owner_status": 0, "read_as_attacker_status": 0, "teardown_success": False, "duration_ms": 0, "error": "Aggressive tests disabled. Use --aggressive.",
         "signals": {}},
        {"chain_id": "CHAIN_013", "resource": "orders", "variant": "INJECTION", "verdict": "ERROR", "score": 0.00,
         "attack_endpoint": "PUT /api/orders/{id}", "create_status": 0, "resource_ids": {},
         "read_as_owner_status": 0, "read_as_attacker_status": 0, "teardown_success": False, "duration_ms": 0, "error": "Aggressive tests disabled. Use --aggressive.",
         "signals": {}},
        {"chain_id": "CHAIN_014", "resource": "users", "variant": "INJECTION", "verdict": "ERROR", "score": 0.00,
         "attack_endpoint": "POST /api/users", "create_status": 0, "resource_ids": {},
         "read_as_owner_status": 0, "read_as_attacker_status": 0, "teardown_success": False, "duration_ms": 0, "error": "Aggressive tests disabled. Use --aggressive.",
         "signals": {}},
        {"chain_id": "CHAIN_015", "resource": "users", "variant": "INJECTION", "verdict": "ERROR", "score": 0.00,
         "attack_endpoint": "PUT /api/users/{user_id}", "create_status": 0, "resource_ids": {},
         "read_as_owner_status": 0, "read_as_attacker_status": 0, "teardown_success": False, "duration_ms": 0, "error": "Aggressive tests disabled. Use --aggressive.",
         "signals": {}},
        {"chain_id": "CHAIN_016", "resource": "create-review", "variant": "INJECTION", "verdict": "ERROR", "score": 0.00,
         "attack_endpoint": "POST /api/create-review", "create_status": 0, "resource_ids": {},
         "read_as_owner_status": 0, "read_as_attacker_status": 0, "teardown_success": False, "duration_ms": 0, "error": "Aggressive tests disabled. Use --aggressive.",
         "signals": {}},
        {"chain_id": "CHAIN_017", "resource": "orders", "variant": "BOLA_HPP", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 106},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_018", "resource": "orders", "variant": "BOLA_ARRAY", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/orders/{id}", "create_status": 201, "resource_ids": {"id": 107},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": True, "duration_ms": 46, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_019", "resource": "users", "variant": "BOLA_HPP", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 505},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_020", "resource": "users", "variant": "BOLA_ARRAY", "verdict": "CONFIRMED", "score": 1.00,
         "attack_endpoint": "GET /api/users/{user_id}", "create_status": 201, "resource_ids": {"user_id": 506},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 1.0, "error_keywords": 1.0, "content_length": 1.0}},
        {"chain_id": "CHAIN_021", "resource": "create-review", "variant": "BOLA_HPP", "verdict": "LIKELY", "score": 0.75,
         "attack_endpoint": "GET /api/fetch-review", "create_status": 200, "resource_ids": {"review_id": 703},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 31, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 0.83, "data_leakage": 0.17, "error_keywords": 1.0, "content_length": 0.50}},
        {"chain_id": "CHAIN_022", "resource": "create-review", "variant": "BOLA_ARRAY", "verdict": "CONFIRMED", "score": 0.92,
         "attack_endpoint": "GET /api/fetch-review", "create_status": 200, "resource_ids": {"review_id": 704},
         "read_as_owner_status": 200, "read_as_attacker_status": 200, "teardown_success": False, "duration_ms": 30, "error": None,
         "signals": {"status_code": 1.0, "structural_similarity": 1.0, "data_leakage": 0.60, "error_keywords": 1.0, "content_length": 1.0}},
    ]


def build_mock_results():
    """18 Benchmark and mock chains across diverse resource categories."""
    sample_json_path = os.path.join(os.path.dirname(__file__), "sample_report.json")
    if os.path.exists(sample_json_path):
        with open(sample_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("results", [])
    return []


def generate_combined():
    live_results = build_live_scan_results()
    mock_results = build_mock_results()

    for r in live_results:
        r["source_label"] = "Live Scan (Target: 127.0.0.1:8000)"
        r["source_type"] = "LIVE"
    for r in mock_results:
        r["source_label"] = "Mock Benchmark"
        r["source_type"] = "MOCK"

    combined_results = live_results + mock_results

    # Summary calculations
    def summarize(res_list):
        return {
            "total": len(res_list),
            "confirmed": sum(1 for r in res_list if r.get("verdict") == "CONFIRMED"),
            "likely": sum(1 for r in res_list if r.get("verdict") == "LIKELY"),
            "possible": sum(1 for r in res_list if r.get("verdict") == "POSSIBLE"),
            "secure": sum(1 for r in res_list if r.get("verdict") == "SECURE"),
            "errors": sum(1 for r in res_list if r.get("verdict") == "ERROR"),
            "results": res_list
        }

    all_data = {
        "combined": summarize(combined_results),
        "live": summarize(live_results),
        "mock": summarize(mock_results)
    }

    c = all_data["combined"]
    l = all_data["live"]
    m = all_data["mock"]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APIGhost Combined Scan Report — Multi-Dataset Security Dashboard</title>
    <style>
        :root {{
            --bg-base: #0a0d14;
            --bg-surface: #111726;
            --bg-card: #161f33;
            --bg-card-hover: #1c2742;
            --border: #23304d;
            --border-light: #2e3e63;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            
            --cyan: #06b6d4;
            --cyan-glow: rgba(6, 182, 212, 0.15);
            --red: #ef4444;
            --red-glow: rgba(239, 68, 68, 0.18);
            --amber: #f59e0b;
            --amber-glow: rgba(245, 158, 11, 0.15);
            --green: #10b981;
            --green-glow: rgba(16, 185, 129, 0.15);
            --purple: #a855f7;
            --blue: #3b82f6;
            --gray: #64748b;

            --radius: 10px;
            --shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            line-height: 1.5;
            padding: 30px 40px;
            min-height: 100vh;
        }}

        code, pre, .mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }}

        /* ── Header ── */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .brand-logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-logo svg {{
            width: 36px;
            height: 36px;
            color: var(--cyan);
            filter: drop-shadow(0 0 10px var(--cyan-glow));
        }}
        .brand-title {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #fff 30%, var(--cyan) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand-subtitle {{
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 2px;
        }}
        .header-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }}
        .badge-combined {{
            background: rgba(168, 85, 247, 0.15);
            color: var(--purple);
            border: 1px solid rgba(168, 85, 247, 0.4);
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 11px;
            display: inline-block;
            margin-top: 4px;
        }}

        /* ── Multi-Report Dataset Tabs ── */
        .dataset-nav {{
            display: flex;
            gap: 12px;
            margin-bottom: 28px;
            background: var(--bg-surface);
            padding: 6px;
            border-radius: 12px;
            border: 1px solid var(--border);
        }}
        .dataset-tab {{
            flex: 1;
            padding: 12px 18px;
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-muted);
            font-weight: 700;
            font-size: 13px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s ease;
        }}
        .dataset-tab:hover {{
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.04);
        }}
        .dataset-tab.active {{
            background: var(--bg-card);
            color: var(--text-main);
            border-color: var(--border-light);
            box-shadow: 0 2px 12px rgba(0,0,0,0.4);
        }}
        .tab-pill {{
            background: rgba(255,255,255,0.1);
            padding: 2px 7px;
            border-radius: 10px;
            font-size: 11px;
        }}
        .dataset-tab.active .tab-pill {{
            background: var(--cyan);
            color: #000;
            font-weight: 800;
        }}

        /* ── Executive Stat Cards ── */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .stat-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 18px 20px;
            position: relative;
            overflow: hidden;
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: 800;
            margin-top: 8px;
            font-family: ui-monospace, SFMono-Regular, monospace;
        }}

        /* ── Charts Grid ── */
        .analytics-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 28px;
        }}
        .analytics-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
        }}
        .analytics-card-title {{
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-main);
        }}
        .donut-container {{
            display: flex;
            align-items: center;
            justify-content: space-around;
            min-height: 160px;
        }}
        .donut-legend {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            font-size: 13px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .legend-color {{
            width: 10px;
            height: 10px;
            border-radius: 3px;
        }}

        /* ── Bar Track ── */
        .bar-chart-container {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .bar-row {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .bar-row-header {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
        }}
        .bar-track {{
            background: rgba(255, 255, 255, 0.05);
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
        }}
        .bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.6s ease;
        }}

        /* ── Findings Section & Filter Tabs ── */
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .filter-tabs {{
            display: flex;
            gap: 6px;
            background: var(--bg-surface);
            padding: 4px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .filter-btn {{
            padding: 6px 12px;
            border-radius: 6px;
            border: none;
            background: transparent;
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .filter-btn:hover {{
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }}
        .filter-btn.active {{
            background: var(--bg-card);
            color: var(--cyan);
            box-shadow: 0 1px 4px rgba(0,0,0,0.3);
        }}
        .search-bar {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 12px;
            min-width: 220px;
        }}

        /* ── Findings Table ── */
        .table-container {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: var(--shadow);
            margin-bottom: 32px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        thead tr {{
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border);
        }}
        th {{
            padding: 12px 16px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            font-weight: 700;
        }}
        tbody tr.finding-row {{
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            cursor: pointer;
            transition: background 0.15s ease;
        }}
        tbody tr.finding-row:hover {{
            background: var(--bg-card-hover);
        }}
        tbody tr.finding-row.hidden {{
            display: none;
        }}
        td {{
            padding: 14px 16px;
            vertical-align: middle;
        }}
        .verdict-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}
        .verdict-CONFIRMED {{ background: var(--red-glow); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.4); }}
        .verdict-LIKELY    {{ background: var(--amber-glow); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.4); }}
        .verdict-POSSIBLE  {{ background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .verdict-SECURE    {{ background: var(--green-glow); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.4); }}
        .verdict-ERROR     {{ background: rgba(100, 116, 139, 0.15); color: var(--gray); border: 1px solid rgba(100, 116, 139, 0.4); }}

        /* ── Collapsible Drawer ── */
        .details-row {{
            display: none;
            background: #0d121f;
        }}
        .details-row.open {{
            display: table-row;
        }}
        .details-content {{
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
        }}
        .flow-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }}
        .flow-step {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
        }}
        .step-header {{
            font-size: 12px;
            font-weight: 700;
            color: var(--text-muted);
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
        }}
        .signals-box {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 16px;
        }}
        .poc-box {{
            background: #060910;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
        }}
        .poc-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .copy-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            color: var(--text-main);
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
        }}

        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-dim);
            padding-top: 24px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>

    <!-- ── Header ── -->
    <div class="header">
        <div class="brand-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
            <div>
                <div class="brand-title">APIGhost Combined Security Dashboard</div>
                <div class="brand-subtitle">Stateful Dual-Token BOLA & Authorization Scanner</div>
            </div>
        </div>
        <div class="header-meta">
            <div>Multi-Dataset Consolidation</div>
            <div class="badge-combined">COMBINED MASTER REPORT</div>
        </div>
    </div>

    <!-- ── Multi-Report Dataset Tabs ── -->
    <div class="dataset-nav">
        <button class="dataset-tab active" onclick="switchDataset('combined')" id="tab-combined">
            <span>🌟 Combined Overview</span>
            <span class="tab-pill">{c['total']} Chains</span>
        </button>
        <button class="dataset-tab" onclick="switchDataset('live')" id="tab-live">
            <span>⚡ Live Target Scan</span>
            <span class="tab-pill">{l['total']} Chains</span>
        </button>
        <button class="dataset-tab" onclick="switchDataset('mock')" id="tab-mock">
            <span>🔬 Benchmark / Sample</span>
            <span class="tab-pill">{m['total']} Chains</span>
        </button>
    </div>

    <!-- ── Executive Stat Cards ── -->
    <div class="stats-grid">
        <div class="stat-card" style="border-left: 4px solid var(--cyan);">
            <div class="stat-label">Total Chains <span>🔗</span></div>
            <div class="stat-value" id="stat-total" style="color: var(--cyan);">{c['total']}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--red);">
            <div class="stat-label">Confirmed BOLA <span>🔴</span></div>
            <div class="stat-value" id="stat-confirmed" style="color: var(--red);">{c['confirmed']}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--amber);">
            <div class="stat-label">Likely BOLA <span>🟡</span></div>
            <div class="stat-value" id="stat-likely" style="color: var(--amber);">{c['likely']}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--green);">
            <div class="stat-label">Secure <span>🟢</span></div>
            <div class="stat-value" id="stat-secure" style="color: var(--green);">{c['secure']}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--gray);">
            <div class="stat-label">Errors / Aggressive <span>⚪</span></div>
            <div class="stat-value" id="stat-errors" style="color: var(--gray);">{c['errors']}</div>
        </div>
    </div>

    <!-- ── Visual Analytics Grid ── -->
    <div class="analytics-grid">
        <!-- Donut Chart -->
        <div class="analytics-card">
            <div class="analytics-card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0110 10h-10z"/></svg>
                Verdict Distribution
            </div>
            <div class="donut-container">
                <svg id="donut-chart" width="160" height="160" viewBox="0 0 42 42"></svg>
                <div class="donut-legend" id="donut-legend"></div>
            </div>
        </div>

        <!-- Attack Vector Breakdown -->
        <div class="analytics-card">
            <div class="analytics-card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V10M18 20V4M6 20v-4"/></svg>
                Attack Vector Breakdown
            </div>
            <div class="bar-chart-container" id="bar-chart-container"></div>
        </div>
    </div>

    <!-- ── Vulnerability Score Results Graph ── -->
    <div class="analytics-card" style="margin-bottom: 32px;">
        <div class="analytics-card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            Vulnerability Score Results
        </div>
        <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 16px;">
            BOLA confidence score per attack chain across the active dataset.
        </div>
        <div id="vuln-score-chart" style="display: flex; flex-direction: column; gap: 10px;"></div>
    </div>

    <!-- ── Findings & Chains Explorer ── -->
    <div class="section-header">
        <div class="section-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
            Attack Chains & Detailed Findings
        </div>
        <div class="filter-tabs">
            <button class="filter-btn active" onclick="setFilter('ALL')">All</button>
            <button class="filter-btn" onclick="setFilter('VULN')">Vulnerabilities</button>
            <button class="filter-btn" onclick="setFilter('CONFIRMED')">Confirmed</button>
            <button class="filter-btn" onclick="setFilter('LIKELY')">Likely</button>
            <button class="filter-btn" onclick="setFilter('SECURE')">Secure</button>
            <button class="filter-btn" onclick="setFilter('ERROR')">Errors</button>
        </div>
        <input type="text" id="search-input" class="search-bar" placeholder="Search paths, chains, methods..." oninput="applySearch()">
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th>Chain ID</th>
                    <th>Dataset</th>
                    <th>Resource</th>
                    <th>Variant</th>
                    <th>Attack Endpoint</th>
                    <th>Verdict</th>
                    <th>Score</th>
                    <th>Status (A/B)</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody id="findings-tbody"></tbody>
        </table>
    </div>

    <!-- ── Footer ── -->
    <footer class="footer">
        <div>APIGhost Combined Multi-Dataset Security Report</div>
        <div class="mono" style="margin-top: 4px;">Stateful BOLA Detection Engine — Open Source</div>
    </footer>

    <!-- ── Embedded Datasets ── -->
    <script id="all-report-data" type="application/json">
    {json.dumps(all_data)}
    </script>

    <script>
        const allData = JSON.parse(document.getElementById('all-report-data').textContent);
        let currentDatasetKey = 'combined';
        let currentFilter = 'ALL';

        function switchDataset(key) {{
            currentDatasetKey = key;
            document.querySelectorAll('.dataset-tab').forEach(t => t.classList.remove('active'));
            document.getElementById(`tab-${{key}}`).classList.add('active');
            renderDashboard();
        }}

        function renderDashboard() {{
            const data = allData[currentDatasetKey];
            
            // Update Stat Cards
            document.getElementById('stat-total').textContent = data.total;
            document.getElementById('stat-confirmed').textContent = data.confirmed;
            document.getElementById('stat-likely').textContent = data.likely;
            document.getElementById('stat-secure').textContent = data.secure;
            document.getElementById('stat-errors').textContent = data.errors;

            // Render Charts
            renderDonutChart(data);
            renderBarChart(data);
            renderVulnScoreChart(data);
            renderTable(data);
        }}

        function renderDonutChart(data) {{
            const total = data.total || 1;
            const slices = [
                {{ name: 'Confirmed', val: data.confirmed, color: '#ef4444' }},
                {{ name: 'Likely', val: data.likely, color: '#f59e0b' }},
                {{ name: 'Possible', val: data.possible || 0, color: '#f97316' }},
                {{ name: 'Secure', val: data.secure, color: '#10b981' }},
                {{ name: 'Errors', val: data.errors, color: '#64748b' }}
            ];

            const svg = document.getElementById('donut-chart');
            let accumulatedPercent = 0;
            let paths = '';

            slices.forEach(slice => {{
                if (slice.val === 0) return;
                const percent = (slice.val / total) * 100;
                const dashArray = `${{percent}} ${{100 - percent}}`;
                const dashOffset = 100 - accumulatedPercent + 25;
                paths += `<circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="${{slice.color}}" stroke-width="4.5" stroke-dasharray="${{dashArray}}" stroke-dashoffset="${{dashOffset}}"></circle>`;
                accumulatedPercent += percent;
            }});

            if (total === 0) {{
                paths = `<circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#23304d" stroke-width="4.5"></circle>`;
            }}

            svg.innerHTML = paths + `
                <g class="donut-text">
                    <text x="50%" y="46%" text-anchor="middle" font-size="7" font-weight="bold" fill="#f1f5f9">${{data.total}}</text>
                    <text x="50%" y="58%" text-anchor="middle" font-size="3" fill="#64748b" text-transform="uppercase">Chains</text>
                </g>
            `;

            const legend = document.getElementById('donut-legend');
            legend.innerHTML = slices.map(s => `
                <div class="legend-item"><div class="legend-color" style="background: ${{s.color}};"></div> ${{s.name}}: ${{s.val}}</div>
            `).join('');
        }}

        function renderBarChart(data) {{
            const counts = {{}};
            data.results.forEach(r => {{
                const v = r.variant || (r.chain && r.chain.variant) || 'OTHER';
                counts[v] = (counts[v] || 0) + 1;
            }});

            const container = document.getElementById('bar-chart-container');
            const max = Math.max(...Object.values(counts), 1);
            container.innerHTML = Object.entries(counts).sort((a,b) => b[1] - a[1]).map(([v, c]) => `
                <div class="bar-row">
                    <div class="bar-row-header">
                        <span class="mono">${{v}}</span>
                        <strong>${{c}}</strong>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: ${{(c/max)*100}}%; background: linear-gradient(90deg, #06b6d4, #3b82f6);"></div>
                    </div>
                </div>
            `).join('');
        }}

        function renderVulnScoreChart(data) {{
            const chart = document.getElementById('vuln-score-chart');
            chart.innerHTML = data.results.map(r => {{
                const chainId = r.chain_id || (r.chain && r.chain.chain_id);
                const score = typeof r.score === 'number' ? r.score : 0;
                const verdict = r.verdict || (r.verdict && r.verdict.value) || 'UNKNOWN';
                const ep = r.attack_endpoint || (r.chain && r.chain.attack ? r.chain.attack.method + ' ' + r.chain.attack.path : (r.chain && r.chain.read ? r.chain.read.method + ' ' + r.chain.read.path : ''));
                const color = score >= 0.75 ? 'var(--red)' : (score >= 0.5 ? 'var(--amber)' : (score >= 0.25 ? '#f97316' : 'var(--green)'));
                
                return `
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div class="mono" style="min-width: 90px; font-size: 11px; font-weight: 700; color: var(--cyan);">${{chainId}}</div>
                        <div style="flex: 1; display: flex; flex-direction: column; gap: 3px;">
                            <div style="display: flex; justify-content: space-between; font-size: 11px;">
                                <span class="mono text-dim">${{ep}}</span>
                                <span class="verdict-badge verdict-${{verdict}}" style="font-size: 9px; padding: 1px 6px;">${{verdict}}</span>
                            </div>
                            <div class="bar-track" style="height: 12px; border-radius: 6px;">
                                <div class="bar-fill" style="width: ${{score * 100}}%; height: 100%; border-radius: 6px; background: ${{color}};"></div>
                            </div>
                        </div>
                        <div class="mono" style="min-width: 44px; text-align: right; font-size: 13px; font-weight: 800; color: ${{color}};">
                            ${{score.toFixed(2)}}
                        </div>
                    </div>
                `;
            }}).join('');
        }}

        function renderTable(data) {{
            const tbody = document.getElementById('findings-tbody');
            tbody.innerHTML = data.results.map(r => {{
                const chainId = r.chain_id || (r.chain && r.chain.chain_id);
                const resource = r.resource || (r.chain && r.chain.resource_name) || '-';
                const variant = r.variant || (r.chain && r.chain.variant) || 'READ';
                const verdict = r.verdict || (r.verdict && r.verdict.value) || 'UNKNOWN';
                const score = typeof r.score === 'number' ? r.score : 0;
                const ep = r.attack_endpoint || (r.chain && r.chain.attack ? r.chain.attack.method + ' ' + r.chain.attack.path : (r.chain && r.chain.read ? r.chain.read.method + ' ' + r.chain.read.path : ''));
                const ownerStatus = r.read_as_owner_status || '-';
                const attackerStatus = r.read_as_attacker_status || '-';
                const duration = r.duration_ms || 0;
                const sourceBadge = r.source_type === 'LIVE' ? '<span style="color: var(--cyan); font-weight: 700;">⚡ Live</span>' : '<span style="color: var(--purple); font-weight: 700;">🔬 Mock</span>';

                return `
                    <tr class="finding-row" id="row-${{chainId}}" data-verdict="${{verdict}}" onclick="toggleDetails('${{chainId}}')">
                        <td style="text-align: center; color: var(--text-dim);"><span id="icon-${{chainId}}">▶</span></td>
                        <td class="mono" style="font-weight: 700; color: var(--cyan);">${{chainId}}</td>
                        <td>${{sourceBadge}}</td>
                        <td style="font-weight: 600;">${{resource}}</td>
                        <td class="mono text-dim" style="font-size: 11px;">${{variant}}</td>
                        <td class="mono" style="font-size: 12px;">${{ep}}</td>
                        <td><span class="verdict-badge verdict-${{verdict}}">${{verdict}}</span></td>
                        <td class="mono" style="font-weight: 700;">${{score.toFixed(2)}}</td>
                        <td class="mono" style="font-size: 12px;">${{ownerStatus}} / ${{attackerStatus}}</td>
                        <td class="mono text-dim" style="font-size: 11px;">${{duration}}ms</td>
                    </tr>
                    <tr class="details-row" id="details-${{chainId}}">
                        <td colspan="10">
                            <div class="details-content">
                                <div class="flow-grid">
                                    <div class="flow-step">
                                        <div class="step-header">Phase 1: Setup (User A)</div>
                                        <div style="font-size: 12px;">Created with status: <strong style="color: var(--green);">${{r.create_status || 201}}</strong></div>
                                        <div class="mono text-dim" style="font-size: 11px; margin-top: 4px;">Extracted: ${{JSON.stringify(r.resource_ids || {{}})}}</div>
                                    </div>
                                    <div class="flow-step">
                                        <div class="step-header">Phase 2: Attack (User B)</div>
                                        <div style="font-size: 12px;">Attacker Status: <strong style="color: ${{verdict === 'CONFIRMED' || verdict === 'LIKELY' ? 'var(--red)' : 'var(--green)'}};">${{attackerStatus}}</strong></div>
                                        <div style="font-size: 12px;">Owner Baseline: <strong class="text-dim">${{ownerStatus}}</strong></div>
                                    </div>
                                    <div class="flow-step">
                                        <div class="step-header">Phase 3: Teardown</div>
                                        <div style="font-size: 12px;">Cleaned Up: <strong>${{r.teardown_success ? 'Yes' : 'No'}}</strong></div>
                                    </div>
                                </div>
                                <div class="poc-box">
                                    <div class="poc-header">
                                        <span class="poc-title mono text-dim" style="font-size: 12px;">Reproduction PoC (cURL)</span>
                                        <button class="copy-btn" onclick="copyPoC('poc-${{chainId}}', event)">Copy cURL</button>
                                    </div>
                                    <pre class="mono" id="poc-${{chainId}}" style="font-size: 11px; color: #a5f3fc;">curl -X GET "http://127.0.0.1:8000/api/${{resource}}" -H "Authorization: Bearer &lt;ATTACKER_TOKEN_B&gt;"</pre>
                                </div>
                            </div>
                        </td>
                    </tr>
                `;
            }}).join('');
        }}

        function toggleDetails(chainId) {{
            const details = document.getElementById(`details-${{chainId}}`);
            const icon = document.getElementById(`icon-${{chainId}}`);
            if (!details) return;
            const isOpen = details.classList.contains('open');
            if (isOpen) {{
                details.classList.remove('open');
                if (icon) icon.textContent = '▶';
            }} else {{
                details.classList.add('open');
                if (icon) icon.textContent = '▼';
            }}
        }}

        function setFilter(filter) {{
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            applyFilterAndSearch();
        }}

        function applySearch() {{
            applyFilterAndSearch();
        }}

        function applyFilterAndSearch() {{
            const q = document.getElementById('search-input').value.toLowerCase().trim();
            const rows = document.querySelectorAll('tr.finding-row');
            rows.forEach(r => {{
                const v = r.getAttribute('data-verdict');
                const text = r.innerText.toLowerCase();
                let matchesF = (currentFilter === 'ALL') || 
                               (currentFilter === 'VULN' && (v === 'CONFIRMED' || v === 'LIKELY')) ||
                               (v === currentFilter);
                let matchesQ = !q || text.includes(q);
                r.classList.toggle('hidden', !(matchesF && matchesQ));
            }});
        }}

        function copyPoC(id, ev) {{
            ev.stopPropagation();
            const text = document.getElementById(id).innerText;
            navigator.clipboard.writeText(text).then(() => {{
                const b = ev.target;
                const old = b.innerText;
                b.innerText = 'Copied!';
                setTimeout(() => b.innerText = old, 1500);
            }});
        }}

        document.addEventListener('DOMContentLoaded', () => {{
            renderDashboard();
        }});
    </script>
</body>
</html>
"""

    combined_html_path = os.path.join(os.path.dirname(__file__), "combined_report.html")
    primary_html_path = os.path.join(os.path.dirname(__file__), "report.html")

    with open(combined_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"  ✅ Combined Report saved:  {combined_html_path}")

    with open(primary_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"  ✅ Primary report.html synced: {primary_html_path}")

    print(f"\n📊 Consolidated Multi-Dataset Summary:")
    print(f"  🌟 Total Aggregated Chains: {c['total']}")
    print(f"  ⚡ Live Scan Chains:        {l['total']} (9 Confirmed BOLA)")
    print(f"  🔬 Mock Benchmark Chains:   {m['total']} (5 Confirmed BOLA)")
    print(f"  🔴 Total Confirmed:         {c['confirmed']}")
    print(f"  🟡 Total Likely:            {c['likely']}")
    print(f"  🟢 Total Secure:            {c['secure']}")
    print(f"  ⚪ Total Errors:            {c['errors']}")

    print(f"\n🌐 Opening Combined Report in browser...")
    try:
        os.startfile(combined_html_path)
    except Exception:
        import webbrowser
        webbrowser.open(combined_html_path)


if __name__ == "__main__":
    generate_combined()
