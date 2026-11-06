#!/usr/bin/env python3
"""wallet-alert: watch Base wallets and get a rug warning on every new token they receive.

Polls a Base RPC for ERC-20 Transfer logs INTO the wallets you list. For each token seen for the first time it
asks the CyberWareX safety oracle (https://oracle.cyberwarex.com) for a verdict (ALLOW, LIMIT, RECHECK, BLOCK)
and an A-F grade, then prints the alert or sends it to your Telegram chat.

Python 3.9+ standard library only. No keys needed to start:
  - RPC: Tenderly's public Base gateway (keyless, 1000 blocks per log query). Pass --rpc for your own node.
  - Oracle: 3 free checks per IP per day. After that set CWX_KEY to a prepaid key (see README), or the alert
    says plainly that the token was not checked. A token is never shown as safe without a check.

Usage:
  python3 wallet_alert.py --wallet 0xabc...=whale1 --wallet 0xdef... [--once] [--interval 30]
  TG_BOT_TOKEN=... TG_CHAT_ID=... python3 wallet_alert.py --wallet 0xabc...
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
UA = "wallet-alert/%s (+https://github.com/cyberwarex/wallet-alert)" % __version__
DEFAULT_RPC = "https://base.gateway.tenderly.co"
DEFAULT_ORACLE = "https://oracle.cyberwarex.com"
EXPLORER = "https://basescan.org"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ADDR_RX = re.compile(r"^0x[0-9a-fA-F]{40}$")
VERDICT_TTL = 24 * 3600      # re-check a token after a day; grades can change when a pool or owner changes
MAX_ALERTS_PER_POLL = 20     # an airdrop spray can hit a wallet with hundreds of junk tokens at once
ICON = {"ALLOW": "OK", "LIMIT": "CAUTION", "RECHECK": "CHECK AGAIN", "BLOCK": "DANGER"}


# ---------------------------------------------------------------- RPC

def http_json(url, body=None, headers=None, timeout=20, tries=3):
    """POST (body) or GET (no body) JSON with retries on 429 and 5xx. Returns (status, parsed or None)."""
    h = {"User-Agent": UA, "Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h), timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            if attempt < tries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            return 0, None
    return 0, None


class RPCError(RuntimeError):
    pass


def rpc(url, method, params):
    status, d = http_json(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if not isinstance(d, dict) or "result" not in d:
        err = d.get("error") if isinstance(d, dict) else None
        raise RPCError("%s failed (http %s): %s" % (method, status, err))
    return d["result"]


def topic_for(addr):
    return "0x" + "0" * 24 + addr[2:].lower()


def addr_from_topic(t):
    return "0x" + t[-40:].lower()


def incoming_transfers(rpc_url, wallets, from_block, to_block, max_span):
    """ERC-20 Transfer logs to any of `wallets` in [from_block, to_block], queried in max_span chunks."""
    topics = [TRANSFER, None, [topic_for(w) for w in wallets]]
    out, start = [], from_block
    while start <= to_block:
        end = min(to_block, start + max_span - 1)
        logs = rpc(rpc_url, "eth_getLogs", [{"fromBlock": hex(start), "toBlock": hex(end), "topics": topics}])
        for lg in logs:
            t = lg.get("topics") or []
            if len(t) != 3:          # ERC-721 Transfer has 4 topics (token id indexed); not a coin
                continue
            try:
                value = int(lg.get("data") or "0x0", 16)
            except ValueError:
                continue
            out.append({"token": lg["address"].lower(), "from": addr_from_topic(t[1]), "to": addr_from_topic(t[2]),
                        "value": value, "tx": lg.get("transactionHash"), "block": int(lg["blockNumber"], 16),
                        "log_index": int(lg.get("logIndex") or "0x0", 16)})
        start = end + 1
    out.sort(key=lambda x: (x["block"], x["log_index"]))
    return out


def _decode_string(hexdata):
    """ABI string, or bytes32 (old tokens like MKR). Returns '' on anything odd."""
    b = bytes.fromhex((hexdata or "0x")[2:])
    if len(b) >= 64:
        try:
            ln = int.from_bytes(b[32:64], "big")
            if 0 < ln <= len(b) - 64:
                return b[64:64 + ln].decode("utf-8", "replace").strip()
        except Exception:
            pass
    if len(b) == 32:
        return b.rstrip(b"\0").decode("utf-8", "replace").strip()
    return ""


def token_meta(rpc_url, token):
    sym, dec = "", 18
    try:
        sym = _decode_string(rpc(rpc_url, "eth_call", [{"to": token, "data": "0x95d89b41"}, "latest"]))
    except RPCError:
        pass
    try:
        r = rpc(rpc_url, "eth_call", [{"to": token, "data": "0x313ce567"}, "latest"])
        dec = int(r, 16) if r and r != "0x" else 18
        dec = dec if 0 <= dec <= 36 else 18
    except (RPCError, ValueError):
        pass
    sym = re.sub(r"[^\w.\-$ ]", "", sym)[:16] or "?"   # token names are attacker-controlled text
    return {"symbol": sym, "decimals": dec}


# ---------------------------------------------------------------- oracle

def check_token(oracle, token, key=None, chain="base"):
    """Verdict dict from the oracle. Always returns a dict; 'checked': False when no verdict was obtained."""
    url = "%s/risk/explain?%s" % (oracle.rstrip("/"), urllib.parse.urlencode({"address": token, "chain": chain}))
    headers = {"X-No-Advert": "1"}
    if key:
        headers["X-Subscription-Key"] = key
    else:
        headers["X-Free-Trial"] = "1"
    status, d = http_json(url, headers=headers, timeout=90, tries=2)
    if status == 200 and isinstance(d, dict) and d.get("verdict"):
        rec = d.get("recommendation") or {}
        return {"checked": True, "verdict": d["verdict"], "grade": d.get("grade") or "?",
                "risk": (d.get("risk") or {}).get("overall"), "reasons": list(rec.get("reason_codes") or [])[:4],
                "why": rec.get("why") or ""}
    if status == 402:
        why = ("prepaid key is empty or invalid" if key else
               "free checks for today are used up; set CWX_KEY to keep checking")
        return {"checked": False, "why": why}
    return {"checked": False, "why": "oracle unavailable (http %s)" % status}


# ---------------------------------------------------------------- alert text

def fmt_amount(value, decimals):
    v = value / (10 ** decimals) if decimals else float(value)
    if v >= 1e9:
        return "%.2fB" % (v / 1e9)
    if v >= 1e6:
        return "%.2fM" % (v / 1e6)
    if v >= 1000:
        return "{:,.0f}".format(v)
    return ("%.6f" % v).rstrip("0").rstrip(".") or "0"


def alert_text(tr, meta, verdict, label):
    head = "%s received %s %s" % (label, fmt_amount(tr["value"], meta["decimals"]), meta["symbol"])
    lines = [head]
    if verdict.get("checked"):
        risk = "" if verdict.get("risk") is None else ", risk %s/100" % verdict["risk"]
        lines.append("Rug check: %s (%s, grade %s%s)" % (ICON.get(verdict["verdict"], verdict["verdict"]),
                                                       verdict["verdict"], verdict["grade"], risk))
        if verdict.get("why"):
            lines.append("Why: %s" % verdict["why"])
        if verdict.get("reasons"):
            lines.append("Flags: %s" % ", ".join(verdict["reasons"]))
    else:
        lines.append("Rug check: NOT CHECKED (%s). Treat as unknown, not safe." % verdict.get("why", "no answer"))
    lines.append("Token: %s/token/%s" % (EXPLORER, tr["token"]))
    lines.append("Tx: %s/tx/%s" % (EXPLORER, tr["tx"]))
    return "\n".join(lines)


def send(text, tg_token=None, tg_chat=None):
    """Telegram when both env values are set, otherwise stdout. Returns True if delivered."""
    if not (tg_token and tg_chat):
        print(text + "\n", flush=True)
        return True
    status, d = http_json("https://api.telegram.org/bot%s/sendMessage" % tg_token,
                          {"chat_id": tg_chat, "text": text, "disable_web_page_preview": True}, timeout=20)
    ok = status == 200 and isinstance(d, dict) and d.get("ok")
    if not ok:
        print("telegram send failed (http %s); alert follows:\n%s\n" % (status, text), file=sys.stderr, flush=True)
    return bool(ok)


# ---------------------------------------------------------------- state + loop

def load_state(path):
    try:
        with open(path) as f:
            s = json.load(f)
        if isinstance(s, dict):
            s.setdefault("verdicts", {})
            return s
    except (OSError, ValueError):
        pass
    return {"last_block": None, "verdicts": {}}


def save_state(path, s):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, path)


def parse_wallets(items):
    out = {}
    for it in items:
        addr, _, label = it.partition("=")
        addr = addr.strip()
        if not ADDR_RX.match(addr):
            raise SystemExit("not a wallet address: %r" % addr)
        out[addr.lower()] = label.strip() or (addr[:6] + "..." + addr[-4:])
    if not out:
        raise SystemExit("give at least one --wallet 0x...")
    return out


def poll_once(cfg, state, now=None):
    """One poll: new transfers since the cursor -> alerts. Returns the number of alerts sent."""
    now = now or time.time()
    head = int(rpc(cfg["rpc"], "eth_blockNumber", []), 16)
    if state.get("last_block") is None:
        state["last_block"] = max(0, head - cfg["lookback"])
    start = state["last_block"] + 1
    if start > head:
        return 0
    # Never fall more than max_catchup blocks behind: after a long stop, skip ahead rather than hammer the RPC.
    if head - start > cfg["max_catchup"]:
        start = head - cfg["max_catchup"]
    transfers = incoming_transfers(cfg["rpc"], list(cfg["wallets"]), start, head, cfg["max_span"])
    sent, skipped, meta_cache, unchecked = 0, 0, {}, {}
    for tr in transfers:
        v = state["verdicts"].get(tr["token"]) or unchecked.get(tr["token"])
        fresh = v and now - v.get("at", 0) < VERDICT_TTL
        if fresh and not cfg["every"]:
            continue                      # token already reported recently; only first sightings alert
        if sent >= MAX_ALERTS_PER_POLL:
            skipped += 1
            continue
        if not fresh:
            v = dict(check_token(cfg["oracle"], tr["token"], cfg["key"]), at=now)
            if v.get("checked"):          # a missing check is only remembered for this poll; retried next poll
                state["verdicts"][tr["token"]] = v
            else:
                unchecked[tr["token"]] = v
        if tr["token"] not in meta_cache:
            meta_cache[tr["token"]] = token_meta(cfg["rpc"], tr["token"])
        meta = meta_cache[tr["token"]]
        if cfg["hide_blocked"] and v.get("verdict") == "BLOCK":
            skipped += 1                  # junk airdrops: counted in the summary, not one alert each
            continue
        send(alert_text(tr, meta, v, cfg["wallets"].get(tr["to"], tr["to"])), cfg["tg_token"], cfg["tg_chat"])
        sent += 1
    if skipped:
        send("%d more transfers not shown (cap %d per poll or hidden as BLOCK)." % (skipped, MAX_ALERTS_PER_POLL),
             cfg["tg_token"], cfg["tg_chat"])
    state["last_block"] = head
    if len(state["verdicts"]) > 5000:     # bound the state file
        keep = sorted(state["verdicts"].items(), key=lambda kv: kv[1].get("at", 0))[-2000:]
        state["verdicts"] = dict(keep)
    return sent


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rug-checked alerts for tokens arriving in Base wallets.")
    ap.add_argument("--wallet", action="append", default=[], help="0xADDRESS or 0xADDRESS=label (repeat)")
    ap.add_argument("--rpc", default=os.environ.get("BASE_RPC", DEFAULT_RPC))
    ap.add_argument("--oracle", default=os.environ.get("CWX_ORACLE", DEFAULT_ORACLE))
    ap.add_argument("--interval", type=int, default=30, help="seconds between polls (min 10)")
    ap.add_argument("--lookback", type=int, default=900, help="blocks to scan on first start (Base: 0.2 s each)")
    ap.add_argument("--max-span", type=int, default=1000, help="blocks per log query (keyless Tenderly: 1000)")
    ap.add_argument("--max-catchup", type=int, default=20000, help="most blocks to scan after a long stop")
    ap.add_argument("--state", default="wallet_alert_state.json")
    ap.add_argument("--once", action="store_true", help="poll once and exit")
    ap.add_argument("--every", action="store_true", help="alert on every transfer, not only first sightings")
    ap.add_argument("--hide-blocked", action="store_true", help="count BLOCK-grade airdrops instead of alerting")
    a = ap.parse_args(argv)
    cfg = {"wallets": parse_wallets(a.wallet), "rpc": a.rpc, "oracle": a.oracle, "lookback": max(1, a.lookback),
           "max_span": max(1, a.max_span), "max_catchup": max(a.max_span, a.max_catchup), "every": a.every,
           "hide_blocked": a.hide_blocked, "key": os.environ.get("CWX_KEY") or None,
           "tg_token": os.environ.get("TG_BOT_TOKEN"), "tg_chat": os.environ.get("TG_CHAT_ID")}
    state = load_state(a.state)
    print("watching %d wallet(s) on Base via %s" % (len(cfg["wallets"]), urllib.parse.urlparse(cfg["rpc"]).netloc),
          file=sys.stderr, flush=True)
    while True:
        try:
            poll_once(cfg, state)
            save_state(a.state, state)
        except RPCError as e:
            print("rpc problem, will retry: %s" % e, file=sys.stderr, flush=True)
            if a.once:
                return 1
        if a.once:
            return 0
        time.sleep(max(10, a.interval))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
