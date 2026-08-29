"""
Lightweight Mock Vulnerable API Server for APIGhost Live Scan Testing.
Implements the OpenAPI spec from tests/test_spec.json on port 8000 with real BOLA vulnerabilities.
"""

import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

ORDERS = {}
USERS = {}
REVIEWS = {}

class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quiet logger
        pass

    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

        if self.path.startswith("/api/orders"):
            order_id = len(ORDERS) + 101
            order = {
                "id": order_id,
                "product_id": body.get("product_id", 1),
                "quantity": body.get("quantity", 1),
                "total": 49.99,
                "status": "created",
                "user_email": "owner@company.com"
            }
            ORDERS[order_id] = order
            self._send_json(201, order)
            return

        if self.path.startswith("/api/users"):
            user_id = len(USERS) + 501
            user = {
                "user_id": user_id,
                "username": body.get("username", "testuser"),
                "email": body.get("email", "owner@company.com"),
                "phone": "+1-555-0199"
            }
            USERS[user_id] = user
            self._send_json(201, user)
            return

        if self.path.startswith("/api/create-review"):
            review_id = len(REVIEWS) + 701
            review = {
                "review_id": review_id,
                "product_id": body.get("product_id", 1),
                "rating": body.get("rating", 5),
                "comment": body.get("comment", "Great!"),
                "user_email": "owner@company.com",
                "status": "published"
            }
            REVIEWS[review_id] = review
            self._send_json(200, review)
            return

        self._send_json(404, {"error": "Not Found"})

    def do_GET(self):
        # Order by ID: /api/orders/{id}
        m_order = re.match(r"^/api/orders/(\d+)", self.path)
        if m_order:
            order_id = int(m_order.group(1))
            order = ORDERS.get(order_id, {
                "id": order_id,
                "product_id": 1,
                "quantity": 2,
                "total": 99.99,
                "status": "pending",
                "user_email": "owner@company.com"
            })
            # BOLA Vulnerability: Regardless of token, returns owner's order!
            self._send_json(200, order)
            return

        # User profile: /api/users/{user_id}
        m_user = re.match(r"^/api/users/(\d+)", self.path)
        if m_user:
            user_id = int(m_user.group(1))
            user = USERS.get(user_id, {
                "user_id": user_id,
                "username": "owner_alice",
                "email": "owner@company.com",
                "phone": "+1-555-0199"
            })
            # BOLA Vulnerability: Attacker can read profile!
            self._send_json(200, user)
            return

        # Fetch review: /api/fetch-review?review_id=...
        if "/api/fetch-review" in self.path:
            review_id = 701
            m_rev = re.search(r"review_id=(\d+)", self.path)
            if m_rev:
                review_id = int(m_rev.group(1))
            review = REVIEWS.get(review_id, {
                "review_id": review_id,
                "product_id": 1,
                "rating": 5,
                "comment": "Private review details",
                "user_email": "owner@company.com"
            })
            # BOLA Vulnerability: Attacker can read review!
            self._send_json(200, review)
            return

        self._send_json(404, {"error": "Not Found"})

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        self._send_json(200, {"status": "updated", **body})

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()


def run_server(port=8000):
    server = HTTPServer(("127.0.0.1", port), VulnerableHandler)
    print(f"[*] Mock Vulnerable API listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
