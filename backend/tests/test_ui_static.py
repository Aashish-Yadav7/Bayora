"""Static checks for the chat-style UI (the frontend cannot be built in the review sandbox). Each states WHY."""
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
read = lambda p: (ROOT / p).read_text()


class TestChatUi(unittest.TestCase):
    def test_chat_ui_is_default_and_classic_fallback_exists(self):
        """Users must land on the new UI, but the old dashboard must stay reachable (?classic=1) in case of a regression."""
        m = read("src/main.tsx")
        self.assertIn("<ChatApp />", m); self.assertIn("classic", m); self.assertIn("<App />", m)

    def test_phone_layout_and_accessibility_rules_present(self):
        """Phone support, safe-area insets, reduced-motion and dark theme are core requirements of the redesign."""
        css = read("src/chat/chat.css")
        for needle in ("@media (max-width:760px)", "env(safe-area-inset-bottom)", "prefers-reduced-motion", "data-theme=dark"):
            self.assertIn(needle, css)
        self.assertIn("viewport-fit=cover", read("index.html"))

    def test_ui_never_stores_tokens_or_credentials(self):
        """Only the theme and demo-role choice may live in browser storage; never tokens/passwords."""
        src = read("src/chat/ChatApp.tsx") + read("src/chat/api.ts")
        stored = re.findall(r"(?:sessionStorage|localStorage)\.setItem\('([^']+)'", src)
        self.assertEqual(sorted(stored), ["bayora_active_role", "bayora_theme"])
        self.assertNotIn("Authorization", src)

    def test_every_request_goes_through_csrf_header_helper(self):
        """All API calls in the chat UI must carry X-Requested-With (cookie sessions need it)."""
        self.assertIn("'X-Requested-With': 'bayora'", read("src/chat/api.ts"))
        raw = [l for l in read("src/chat/ChatApp.tsx").splitlines() if "fetch(" in l]
        for l in raw:  # direct fetch is allowed only for health and auth endpoints
            self.assertTrue("/api/health" in l or "/api/auth/" in l, l)

    def test_composer_is_gated_by_role_and_state(self):
        """Red/Blue may only submit in Draft/Ready; evaluator gets lifecycle buttons only."""
        s = read("src/chat/ChatApp.tsx")
        self.assertIn("state === 'Draft' || state === 'Ready'", s)
        self.assertIn("props.role === 'EVALUATOR'", s); self.assertIn("submissions are locked", s)

    def test_lifecycle_action_map_matches_backend_routes(self):
        """Evaluator buttons must hit real endpoints: ready/start/close/results/release."""
        a = read("src/chat/api.ts")
        for path in ("'ready'", "'start'", "'close'", "'results/release'"):
            self.assertIn(path, a)

    def test_unit_script_runs_timeline_tests(self):
        """CI must execute the timeline tests that prove hidden content stays hidden in the UI."""
        self.assertIn("src/chat/timeline.test.ts", read("package.json"))

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_timeline_unit_tests_pass(self):
        """Run the TypeScript timeline tests with Node's built-in type stripping (Node >= 22.6)."""
        r = subprocess.run(["node", "--experimental-strip-types", "--test", "src/chat/timeline.test.ts"], cwd=ROOT, capture_output=True, text=True)
        if "bad option" in r.stderr or "experimental-strip-types" in r.stderr and r.returncode == 9:
            self.skipTest("Node too old for type stripping")
        self.assertEqual(r.returncode, 0, r.stdout[-800:])


if __name__ == "__main__":
    unittest.main()
