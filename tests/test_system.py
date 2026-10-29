"""
End-to-end tests against the real Flask app + real SQLite file (no mocks of our own code).
Only the outbound Roblox HTTP lookup is replaced (the sandbox has no internet).

Run:  python -m unittest discover -s tests -v
"""
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import main  # noqa: E402

STRONG = "Xk9#mPq2$vLw7!Zt"
HW1, HW2 = "HWID-DEVICE-ONE-0001", "HWID-DEVICE-TWO-0002"
UID1, UID2 = 1001, 2002
ROBLOX_USERS = {
    UID1: {"id": UID1, "name": "PlayerOne", "displayName": "Player One", "description": ""},
    UID2: {"id": UID2, "name": "PlayerTwo", "displayName": "Player Two", "description": ""},
}


def fake_roblox(uid):
    u = ROBLOX_USERS.get(uid)
    return dict(u) if u else None


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "t.db")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_app(self, **ov):
        base = {"DB_PATH": self.db, "SCRYPT_N": 2 ** 12, "LOGIN_MAX_FAILS_USER": 5, "LOGIN_MAX_FAILS_IP": 50,
                "CLIENT_RATE": 10000, "ACTIVATE_RATE": 10000, "ADMIN_RATE": 100000}
        base.update(ov)
        app = main.create_app(base)
        app.extensions["roblox_fetch"] = fake_roblox
        return app

    # --- helpers
    def login(self, client, user="admin", pw="admin"):
        return client.post("/api/admin/login", json={"username": user, "password": pw})

    def post(self, client, url, csrf, body=None):
        return client.post(url, json=body or {}, headers={"X-CSRF-Token": csrf})

    def admin_session(self, app, pw=STRONG):
        c = app.test_client()
        con = sqlite3.connect(self.db)
        con.execute("DELETE FROM login_attempts")  # keep brute-force counters from leaking between tests
        con.commit()
        pending = con.execute("SELECT must_change_password FROM admins WHERE username='admin'").fetchone()[0]
        con.close()
        r = self.login(c, pw="admin" if pending else pw)
        data = r.get_json()
        csrf = data["csrf_token"]
        if data["must_change_password"]:
            r = self.post(c, "/api/admin/password", csrf, {"current_password": "admin", "new_password": pw})
            csrf = r.get_json()["csrf_token"]
        return c, csrf

    def gen(self, c, csrf, qty=1, preset="30d", **dur):
        r = self.post(c, "/api/admin/licenses/generate", csrf,
                      {"quantity": qty, "license_type": "Standard", "duration": {"preset": preset, **dur}})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["keys"]

    def activate_full(self, app, key, hwid=HW1, uid=UID1):
        """Full activation incl. profile-code verification (Roblox lookup is faked)."""
        cl = app.test_client()
        body = {"key": key, "hwid": hwid, "hwid_source": "gethwid", "roblox_user_id": uid}
        r = cl.post("/api/client/activate", json=body)
        if r.status_code == 202:
            code = r.get_json()["verification_code"]
            ROBLOX_USERS[uid]["description"] = f"hello {code} bye"
            r = cl.post("/api/client/activate", json={**body, "verify": True})
        return r

    def client_post(self, app, path, key, hwid=HW1, uid=UID1):
        return app.test_client().post(path, json={"key": key, "hwid": hwid, "hwid_source": "gethwid",
                                                  "roblox_user_id": uid})


class TestFlow(Base):
    """Ordered scenario walkthrough sharing one database (tests run alphabetically: t01, t02, ...)."""

    def test_t01_initial_login_forces_password_change(self):
        app = self.make_app()
        c = app.test_client()
        r = self.login(c)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["must_change_password"])
        # Every privileged route is blocked until the password is changed
        for path in ("/api/admin/stats", "/api/admin/licenses", "/api/admin/audit"):
            r = c.get(path)
            self.assertEqual(r.status_code, 403, path)
            self.assertEqual(r.get_json()["code"], "password_change_required")
        csrf = r.get_json() and c.get("/api/admin/me").get_json()["csrf_token"]
        r = self.post(c, "/api/admin/licenses/generate", csrf,
                      {"quantity": 1, "license_type": "Standard", "duration": {"preset": "1d"}})
        self.assertEqual(r.status_code, 403)

    def test_t02_weak_passwords_rejected_then_change_ok_and_default_creds_dead(self):
        app = self.make_app()
        c = app.test_client()
        csrf = self.login(c).get_json()["csrf_token"]
        for weak in ("admin", "short1A!", "alllowercase1234!", "NoSymbolsHere1234"):
            r = self.post(c, "/api/admin/password", csrf, {"current_password": "admin", "new_password": weak})
            self.assertEqual(r.status_code, 400, weak)
        r = self.post(c, "/api/admin/password", csrf, {"current_password": "wrong", "new_password": STRONG})
        self.assertEqual(r.status_code, 401)
        r = self.post(c, "/api/admin/password", csrf, {"current_password": "admin", "new_password": STRONG})
        self.assertEqual(r.status_code, 200)
        # t03: panel now accessible with the rotated session
        self.assertEqual(c.get("/api/admin/stats").status_code, 200)
        # default credentials no longer work
        self.assertEqual(self.login(app.test_client(), pw="admin").status_code, 401)
        self.assertEqual(self.login(app.test_client(), pw=STRONG).status_code, 200)
        # password is not stored in plain text
        row = sqlite3.connect(self.db).execute("SELECT password_hash FROM admins").fetchone()[0]
        self.assertNotIn(STRONG, row)
        self.assertTrue(row.startswith("scrypt$") or row.startswith("$argon2"))

    def test_t04_t05_generate_and_persist_after_restart(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        keys = self.gen(c, csrf, 3, "7d")
        self.assertEqual(len(keys), 3)
        for k in keys:
            self.assertRegex(k["key"], r"^LEXY(-[A-Z2-9]{4}){4}$")
        raw = sqlite3.connect(self.db)
        stored = " ".join(r[0] for r in raw.execute("SELECT key_hash FROM licenses"))
        for k in keys:
            self.assertNotIn(k["key"], stored)  # only hashes stored
        n_before = raw.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
        # simulate server restart: brand-new app object on the same DB file
        app2 = self.make_app()
        r = self.client_post(app2, "/api/client/validate", keys[0]["key"])
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["code"], "not_activated")  # key is recognised (not 'invalid_key')
        c2, csrf2 = self.admin_session(app2)
        lst = c2.get("/api/admin/licenses?per_page=100").get_json()
        self.assertEqual(lst["total"], n_before)
        pending = [i for i in lst["items"] if i["status"] == "pending"]
        self.assertGreaterEqual(len(pending), 3)
        self.assertTrue(all("LEXY-****-****-****-" in i["key_hint"] for i in lst["items"]))

    def test_t06_activation_ok_and_t07_invalid_key(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "7d")[0]["key"]
        cl = app.test_client()
        body = {"key": key, "hwid": HW1, "hwid_source": "gethwid", "roblox_user_id": UID1}
        # first call: must ask for proof of account ownership (no binding yet)
        r = cl.post("/api/client/activate", json=body)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.get_json()["status"], "verification_required")
        code = r.get_json()["verification_code"]
        # verification without placing the code must fail
        ROBLOX_USERS[UID1]["description"] = "nothing here"
        r = cl.post("/api/client/activate", json={**body, "verify": True})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["code"], "verification_failed")
        # with the code in the profile it succeeds
        ROBLOX_USERS[UID1]["description"] = f"about me {code}"
        t0 = int(time.time())
        r = cl.post("/api/client/activate", json={**body, "verify": True})
        self.assertEqual(r.status_code, 200, r.get_json())
        d = r.get_json()
        self.assertEqual(d["status"], "active")
        self.assertEqual(d["roblox"]["username"], "PlayerOne")  # taken from Roblox, not from the client
        self.assertTrue(d["device"]["bound"])
        self.assertAlmostEqual(d["remaining_seconds"], 7 * 86400, delta=10)
        self.assertGreaterEqual(d["server_time"], t0)
        # subsequent validation works
        r = self.client_post(app, "/api/client/validate", key)
        self.assertEqual(r.get_json()["status"], "active")
        # invalid keys
        r = self.client_post(app, "/api/client/validate", "LEXY-AAAA-BBBB-CCCC-DDDD")
        self.assertEqual((r.status_code, r.get_json()["code"]), (403, "invalid_key"))
        r = self.client_post(app, "/api/client/validate", "garbage")
        self.assertEqual(r.status_code, 403)

    def test_t08_expired(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "1d")[0]
        self.assertEqual(self.activate_full(app, key["key"]).status_code, 200)
        con = sqlite3.connect(self.db, isolation_level=None)
        con.execute("UPDATE licenses SET expires_at=? WHERE id=?", (int(time.time()) - 5, key["id"]))
        con.close()
        for path in ("/api/client/validate", "/api/client/activate"):
            r = self.client_post(app, path, key["key"])
            self.assertEqual((r.status_code, r.get_json()["code"]), (403, "expired"), path)
        stats = c.get("/api/admin/stats").get_json()
        self.assertGreaterEqual(stats["expired"], 1)

    def test_t09_t14_revoked_via_panel(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "30d")[0]
        self.assertEqual(self.activate_full(app, key["key"]).status_code, 200)
        r = self.post(c, f"/api/admin/licenses/{key['id']}/revoke", csrf, {"reason": "test"})
        self.assertEqual(r.status_code, 200)
        r = self.client_post(app, "/api/client/validate", key["key"])
        self.assertEqual((r.status_code, r.get_json()["code"]), (403, "revoked"))
        r = self.activate_full(app, key["key"])
        self.assertEqual(r.get_json()["code"], "revoked")
        self.assertEqual(self.post(c, f"/api/admin/licenses/{key['id']}/revoke", csrf).status_code, 409)

    def test_t10_t11_t12_t13_account_hwid_reset(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "30d")[0]
        k, lid = key["key"], key["id"]
        self.assertEqual(self.activate_full(app, k, HW1, UID1).status_code, 200)
        # t10: second Roblox account rejected (validate AND activate)
        for path in ("/api/client/validate", "/api/client/activate"):
            r = self.client_post(app, path, k, HW1, UID2)
            self.assertEqual((r.status_code, r.get_json()["code"]), (403, "account_mismatch"), path)
        # t11: other device rejected even with the right account
        for path in ("/api/client/validate", "/api/client/activate"):
            r = self.client_post(app, path, k, HW2, UID1)
            self.assertEqual((r.status_code, r.get_json()["code"]), (403, "hwid_mismatch"), path)
        # t12: admin resets HWID
        r = self.post(c, f"/api/admin/licenses/{lid}/reset-hwid", csrf, {"reason": "new pc"})
        self.assertEqual(r.status_code, 200)
        d = c.get(f"/api/admin/licenses/{lid}").get_json()["license"]
        self.assertFalse(d["device_bound"])
        # t13: Roblox account must still be linked after the reset
        self.assertEqual(d["roblox_user_id"], UID1)
        self.assertEqual(d["hwid_resets"], 1)
        # old device now needs re-activation; the other account is STILL rejected
        r = self.client_post(app, "/api/client/validate", k, HW2, UID1)
        self.assertEqual(r.get_json()["code"], "hwid_not_bound")
        r = self.client_post(app, "/api/client/activate", k, HW2, UID2)
        self.assertEqual(r.get_json()["code"], "account_mismatch")
        # same account activates on new device without re-verification, expiry unchanged
        before = d["expires_at"]
        r = self.client_post(app, "/api/client/activate", k, HW2, UID1)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["expires_at"], before)
        self.assertEqual(self.client_post(app, "/api/client/validate", k, HW1, UID1).get_json()["code"],
                         "hwid_mismatch")
        # unlink account is a separate, audited action
        r = self.post(c, f"/api/admin/licenses/{lid}/unlink-account", csrf, {"reason": "sold"})
        self.assertEqual(r.status_code, 200)
        d = c.get(f"/api/admin/licenses/{lid}").get_json()
        self.assertIsNone(d["license"]["roblox_user_id"])
        actions = [h["action"] for h in d["history"]]
        for a in ("license.activate", "license.hwid_reset", "license.rebind", "license.unlink_account"):
            self.assertIn(a, actions)

    def test_t15_unavailable_dependencies(self):
        """Backend side of 'API unavailable': Roblox lookup down -> clean 503, nothing is bound."""
        app = self.make_app()
        app.extensions["roblox_fetch"] = lambda uid: None
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "7d")[0]
        cl = app.test_client()
        body = {"key": key["key"], "hwid": HW1, "hwid_source": "gethwid", "roblox_user_id": UID1}
        r = cl.post("/api/client/activate", json=body)
        self.assertEqual(r.status_code, 202)
        r = cl.post("/api/client/activate", json={**body, "verify": True})
        self.assertEqual((r.status_code, r.get_json()["code"]), (503, "roblox_unavailable"))
        d = c.get(f"/api/admin/licenses/{key['id']}").get_json()["license"]
        self.assertEqual(d["status"], "pending")
        # malformed bodies -> consistent JSON errors, never a stack trace
        r = cl.post("/api/client/activate", data="not json", content_type="application/json")
        self.assertIn(r.status_code, (400, 403))
        self.assertFalse(r.get_json()["ok"])

    def test_t16_admin_routes_protected(self):
        app = self.make_app()
        anon = app.test_client()
        routes = [("get", "/api/admin/stats"), ("get", "/api/admin/licenses"), ("get", "/api/admin/licenses/1"),
                  ("get", "/api/admin/audit"), ("get", "/api/admin/me"),
                  ("post", "/api/admin/licenses/generate"), ("post", "/api/admin/licenses/1/revoke"),
                  ("post", "/api/admin/licenses/1/reset-hwid"), ("post", "/api/admin/licenses/1/unlink-account"),
                  ("post", "/api/admin/password"), ("post", "/api/admin/logout")]
        for m, p in routes:
            r = getattr(anon, m)(p, **({"json": {}} if m == "post" else {}))
            self.assertEqual(r.status_code, 401, p)
        # fake cookie / bogus CSRF
        anon.set_cookie("lexy_sid", "forged-session-value")
        self.assertEqual(anon.get("/api/admin/stats").status_code, 401)
        c, csrf = self.admin_session(app)
        r = c.post("/api/admin/licenses/generate", json={"quantity": 1, "license_type": "Standard",
                                                         "duration": {"preset": "1d"}})
        self.assertEqual(r.status_code, 403)  # missing CSRF
        r = c.post("/api/admin/licenses/generate", json={}, headers={"X-CSRF-Token": "x", "Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)  # bad origin
        # a client key/hwid cannot call admin routes; logout kills the session
        self.assertEqual(self.post(c, "/api/admin/logout", csrf).status_code, 200)
        self.assertEqual(c.get("/api/admin/stats").status_code, 401)

    def test_t17_many_keys_no_duplicates_and_input_validation(self):
        app = self.make_app()
        c, csrf = self.admin_session(app)
        keys = self.gen(c, csrf, 500, "permanent")
        vals = [k["key"] for k in keys]
        self.assertEqual(len(set(vals)), 500)
        stats = c.get("/api/admin/stats").get_json()
        self.assertGreaterEqual(stats["pending"], 500)
        # UNIQUE constraint really exists in the DB
        con = sqlite3.connect(self.db, isolation_level=None)
        h = con.execute("SELECT key_hash FROM licenses LIMIT 1").fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO licenses (key_hash,key_hint,license_type,is_permanent,status,created_at)"
                        " VALUES (?,?,?,?,?,?)", (h, "x", "Standard", 1, "pending", 1))
        con.close()  # release the connection so it does not hold the write lock
        bad = [{"quantity": 0}, {"quantity": 501}, {"quantity": "5"}, {"quantity": True},
               {"quantity": 1, "license_type": "Nope", "duration": {"preset": "1d"}},
               {"quantity": 1, "license_type": "Standard", "duration": {"preset": "custom", "custom_value": -1,
                                                                        "custom_unit": "days"}},
               {"quantity": 1, "license_type": "Standard", "duration": {"preset": "custom", "custom_value": 99999,
                                                                        "custom_unit": "days"}}]
        for b in bad:
            self.assertEqual(self.post(c, "/api/admin/licenses/generate", csrf, b).status_code, 400, b)
        # custom duration works
        k = self.gen(c, csrf, 1, "custom", custom_value=90, custom_unit="minutes")[0]
        d = c.get(f"/api/admin/licenses/{k['id']}").get_json()["license"]
        self.assertEqual(d["duration_seconds"], 5400)

    def test_t18_concurrent_activation_single_winner(self):
        import threading
        app = self.make_app()
        c, csrf = self.admin_session(app)
        key = self.gen(c, csrf, 1, "30d")[0]["key"]
        # pre-verify identity for UID1 so both threads race on the final bind
        self.assertEqual(self.activate_full(app, key, HW1, UID1).status_code, 200)
        c2, csrf2 = self.admin_session(app)
        self.post(c2, "/api/admin/licenses/%d/reset-hwid" % c2.get("/api/admin/licenses?q=%s" % key[-4:]).get_json()["items"][0]["id"], csrf2)
        results = []

        def go(hw):
            results.append(self.client_post(app, "/api/client/activate", key, hw, UID1).status_code)
        ts = [threading.Thread(target=go, args=(h,)) for h in ("HWID-RACE-AAAAAA", "HWID-RACE-BBBBBB")]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(results), [200, 403])  # exactly one device wins

    def test_t19_login_bruteforce_lockout_and_stats_and_audit_hygiene(self):
        app = self.make_app()
        self.admin_session(app)
        c = app.test_client()
        codes = [self.login(c, pw=f"wrong-{i}").status_code for i in range(7)]
        self.assertIn(429, codes)
        self.assertEqual(self.login(c, pw=STRONG).status_code, 429)  # still locked
        # audit must never contain secrets
        con = sqlite3.connect(self.db)
        blob = " ".join(str(v) for row in con.execute("SELECT action, reason FROM audit_log") for v in row)
        self.assertNotIn(STRONG, blob)
        self.assertNotRegex(blob, r"LEXY(-[A-Z2-9]{4}){4}")


class TestHardening(Base):
    def test_t20_production_refuses_default_bootstrap(self):
        with self.assertRaises(RuntimeError):
            main.load_config({"ENV": "production", "DB_PATH": self.db, "BOOTSTRAP_PASSWORD": "admin",
                              "SECRET": "s" * 40, "PEPPER": "p" * 40})

    def test_t21_unknown_route_is_404_and_spa_index_served(self):
        import re
        app = self.make_app()
        c = app.test_client()
        self.assertEqual(c.get("/no-existe").status_code, 404)
        r = c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Lexy Hub", r.data)
        # no default credential is pre-filled in any input field
        self.assertIsNone(re.search(rb'<input[^>]*value="admin"', r.data))

    def test_t22_no_credentials_in_client_js(self):
        import re
        app = self.make_app()
        js = app.test_client().get("/static/app.js").data.decode()
        self.assertNotIn('"admin"', js)
        self.assertIsNone(re.search(r'\b(username|password)\s*:\s*["\']', js))  # no hardcoded credential literals


if __name__ == "__main__":
    unittest.main(verbosity=2)
