"""Offline tests: every network call is stubbed (RPC, oracle, Telegram). Run: python3 -m unittest -v"""
import json
import os
import tempfile
import unittest
from unittest import mock

import wallet_alert as wa

W1 = "0x" + "a1" * 20
TOK_OK = "0x" + "b2" * 20
TOK_BAD = "0x" + "c3" * 20
NFT = "0x" + "d4" * 20


def abi_string(s):
    b = s.encode()
    return "0x" + (32).to_bytes(32, "big").hex() + len(b).to_bytes(32, "big").hex() + b.ljust(32, b"\0").hex()


def log(token, to, value, block, idx=0, topics=3):
    t = [wa.TRANSFER, wa.topic_for("0x" + "ee" * 20), wa.topic_for(to)]
    if topics == 4:
        t.append("0x" + "00" * 31 + "07")
    return {"address": token, "topics": t, "data": hex(value), "transactionHash": "0x" + "%064x" % (block * 100 + idx),
            "blockNumber": hex(block), "logIndex": hex(idx)}


class FakeNet:
    """Stands in for http_json: a tiny Base RPC, the oracle and Telegram."""

    def __init__(self, head=1000, logs=(), oracle=None, tg_ok=True):
        self.head, self.logs, self.oracle, self.tg_ok = head, list(logs), oracle or {}, tg_ok
        self.calls, self.sent, self.log_ranges = [], [], []

    def __call__(self, url, body=None, headers=None, timeout=20, tries=3):
        self.calls.append((url, body, headers))
        if "api.telegram.org" in url:
            self.sent.append(body["text"])
            return (200, {"ok": True}) if self.tg_ok else (401, {"ok": False})
        if "/risk/explain" in url:
            tok = url.split("address=")[1].split("&")[0].lower()
            return self.oracle.get(tok, (402, {"status": 402}))
        m, p = body["method"], body["params"]
        if m == "eth_blockNumber":
            return 200, {"result": hex(self.head)}
        if m == "eth_getLogs":
            f = p[0]
            lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            self.log_ranges.append((lo, hi))
            want = set(f["topics"][2])
            return 200, {"result": [lg for lg in self.logs
                                    if lo <= int(lg["blockNumber"], 16) <= hi and lg["topics"][2] in want]}
        if m == "eth_call":
            data = p[0]["data"]
            if data == "0x95d89b41":
                return 200, {"result": abi_string({TOK_OK: "GOOD", TOK_BAD: "SCAM<b>"}.get(p[0]["to"], "X"))}
            return 200, {"result": hex(6 if p[0]["to"] == TOK_OK else 18)}
        return 500, None


def verdict(v, grade, why="", codes=()):
    return 200, {"verdict": v, "grade": grade, "risk": {"overall": 50},
                 "recommendation": {"reason_codes": list(codes), "why": why}}


def cfg(**kw):
    c = {"wallets": {W1: "whale1"}, "rpc": "http://rpc", "oracle": "http://oracle", "lookback": 100, "max_span": 30,
         "max_catchup": 500, "every": False, "hide_blocked": False, "key": None, "tg_token": "T", "tg_chat": "1"}
    c.update(kw)
    return c


class Tests(unittest.TestCase):
    def run_poll(self, net, c, state=None):
        state = state if state is not None else {"last_block": None, "verdicts": {}}
        with mock.patch.object(wa, "http_json", net):
            n = wa.poll_once(c, state, now=1_000_000)
        return n, state

    def test_first_sighting_alerts_with_verdict_and_caps_chunks(self):
        net = FakeNet(head=1000, logs=[log(TOK_OK, W1, 2_500_000, 950), log(TOK_OK, W1, 1, 960, 1),
                                       log(TOK_BAD, W1, 10**21, 990)],
                      oracle={TOK_OK: verdict("ALLOW", "A", "trade simulation passed"),
                              TOK_BAD: verdict("BLOCK", "F", "cannot sell", ["HONEYPOT"])})
        n, st = self.run_poll(net, cfg())
        self.assertEqual(n, 2)                                 # second GOOD transfer is not a first sighting
        self.assertIn("whale1 received 2.5 GOOD", net.sent[0])
        self.assertIn("OK (ALLOW, grade A", net.sent[0])
        self.assertIn("DANGER (BLOCK, grade F", net.sent[1])
        self.assertIn("HONEYPOT", net.sent[1])
        self.assertIn("SCAMb", net.sent[1])                    # token text is sanitised
        self.assertEqual(st["last_block"], 1000)
        self.assertTrue(all(hi - lo + 1 <= 30 for lo, hi in net.log_ranges))
        self.assertEqual(net.log_ranges[0][0], 901)            # lookback 100 from head 1000

    def test_no_check_is_never_shown_as_safe_and_not_cached(self):
        net = FakeNet(logs=[log(TOK_OK, W1, 5, 990), log(TOK_OK, W1, 6, 995)])   # oracle answers 402
        n, st = self.run_poll(net, cfg())
        self.assertEqual(n, 1)                                 # one oracle call per token per poll, not per transfer
        self.assertEqual(sum("/risk/explain" in c[0] for c in net.calls), 1)
        self.assertIn("NOT CHECKED", net.sent[0])
        self.assertIn("not safe", net.sent[0])
        self.assertNotIn(TOK_OK, st["verdicts"])               # retried next poll

    def test_free_trial_header_or_key(self):
        net = FakeNet(logs=[log(TOK_OK, W1, 5, 990)], oracle={TOK_OK: verdict("ALLOW", "A")})
        self.run_poll(net, cfg())
        h = [c[2] for c in net.calls if "/risk/explain" in c[0]][0]
        self.assertEqual(h.get("X-Free-Trial"), "1")
        self.assertNotIn("X-Subscription-Key", h)
        net = FakeNet(logs=[log(TOK_OK, W1, 5, 990)], oracle={TOK_OK: (402, {})})
        self.run_poll(net, cfg(key="cwx_test"))
        h = [c[2] for c in net.calls if "/risk/explain" in c[0]][0]
        self.assertEqual(h.get("X-Subscription-Key"), "cwx_test")
        self.assertIn("prepaid key is empty", net.sent[0])

    def test_cursor_resumes_and_cached_verdict_skips(self):
        net = FakeNet(head=1000, logs=[log(TOK_OK, W1, 5, 990)], oracle={TOK_OK: verdict("ALLOW", "A")})
        _, st = self.run_poll(net, cfg())
        net2 = FakeNet(head=1010, logs=[log(TOK_OK, W1, 7, 1005)], oracle={TOK_OK: verdict("ALLOW", "A")})
        n, st = self.run_poll(net2, cfg(), st)
        self.assertEqual(n, 0)
        self.assertEqual(net2.log_ranges, [(1001, 1010)])
        self.assertFalse(any("/risk/explain" in c[0] for c in net2.calls))
        n, _ = self.run_poll(FakeNet(head=1020, logs=[log(TOK_OK, W1, 7, 1015)]), cfg(every=True), st)
        self.assertEqual(n, 1)

    def test_nft_and_other_wallets_ignored(self):
        net = FakeNet(logs=[log(NFT, W1, 0, 990, topics=4), log(TOK_OK, "0x" + "99" * 20, 5, 991)])
        n, _ = self.run_poll(net, cfg())
        self.assertEqual(n, 0)
        self.assertEqual(net.sent, [])

    def test_catchup_is_bounded(self):
        net = FakeNet(head=100_000)
        self.run_poll(net, cfg(), {"last_block": 10, "verdicts": {}})
        self.assertEqual(net.log_ranges[0][0], 100_000 - 500)

    def test_alert_cap_and_hide_blocked(self):
        toks = ["0x%040x" % i for i in range(1, 26)]
        net = FakeNet(logs=[log(t, W1, 1, 990, i) for i, t in enumerate(toks)],
                      oracle={t: verdict("BLOCK", "F") for t in toks})
        n, _ = self.run_poll(net, cfg())
        self.assertEqual(n, wa.MAX_ALERTS_PER_POLL)
        self.assertIn("5 more transfers not shown", net.sent[-1])
        net = FakeNet(logs=[log(TOK_BAD, W1, 1, 990)], oracle={TOK_BAD: verdict("BLOCK", "F")})
        n, _ = self.run_poll(net, cfg(hide_blocked=True))
        self.assertEqual(n, 0)
        self.assertIn("1 more transfers not shown", net.sent[0])

    def test_rpc_error_raises_and_state_untouched(self):
        st = {"last_block": 5, "verdicts": {}}
        with mock.patch.object(wa, "http_json", lambda *a, **k: (429, {"error": {"message": "slow down"}})):
            with self.assertRaises(wa.RPCError):
                wa.poll_once(cfg(), st)
        self.assertEqual(st["last_block"], 5)

    def test_stdout_when_no_telegram_and_tg_failure_falls_back(self):
        with mock.patch("builtins.print") as p:
            self.assertTrue(wa.send("hi"))
            p.assert_called_once()
        net = FakeNet(tg_ok=False)
        with mock.patch.object(wa, "http_json", net), mock.patch("builtins.print") as p:
            self.assertFalse(wa.send("hi", "T", "1"))
            self.assertIn("telegram send failed", p.call_args[0][0])

    def test_helpers(self):
        self.assertEqual(wa.fmt_amount(1_234_567_000_000, 6), "1.23M")
        self.assertEqual(wa.fmt_amount(15 * 10**17, 18), "1.5")
        self.assertEqual(wa._decode_string("0x" + b"MKR".ljust(32, b"\0").hex()), "MKR")
        self.assertEqual(wa._decode_string("0x"), "")
        self.assertEqual(wa.parse_wallets([W1.upper().replace("0X", "0x") + "=me"]), {W1: "me"})
        with self.assertRaises(SystemExit):
            wa.parse_wallets(["0x123"])

    def test_state_roundtrip(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.json")
        self.assertEqual(wa.load_state(p), {"last_block": None, "verdicts": {}})
        wa.save_state(p, {"last_block": 7, "verdicts": {"x": {"at": 1}}})
        self.assertEqual(wa.load_state(p)["last_block"], 7)
        with open(p, "w") as f:
            f.write("{broken")
        self.assertIsNone(wa.load_state(p)["last_block"])


if __name__ == "__main__":
    unittest.main()
