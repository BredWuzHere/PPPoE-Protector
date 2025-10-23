#!/usr/bin/env python3
"""
pppoe_protector.py
Network-based PPPoE/ICMPv6/ND defender.
Monitors PPPoE discovery/session, PPP LCP, ICMPv6 echo, and ND (NS/NA) traffic
for suspicious patterns and can optionally block offenders at the host firewall.

Designed as a defensive countermeasure for devices that may be targeted by
noisy PPPoE/IPv6 exploits. Does NOT perform any exploit activity.
Dependencies:
  - Python3
  - scapy (pip install scapy)
  - nftables (recommended) OR ip6tables (fallback) for auto-blocking
Run:
  sudo python3 pppoe_protector.py --iface eth0
  sudo python3 pppoe_protector.py --iface eth0 --auto-block --block-time 600

Copyright (C) 2025 Brendan Sales
This software may be modified and distributed under the terms of the MIT license.

Inspired by Andy Nguyen’s ppwn PS4 exploit (heap overflow research). This project is a defensive implementation — a network-level protector that detects and mitigates the noisy PPPoE / ICMPv6 patterns used by the exploit. Made for learning and defense. 
Credits: Andy Nguyen.

"""

from __future__ import annotations
import argparse
import logging
import subprocess
import time
import threading
from collections import defaultdict, deque
from typing import Optional, Dict, Deque, Tuple

from scapy.all import (
    sniff,
    Ether,
    PPPoED,
    PPPoE,
    PPP,
    PPP_LCP,
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptSrcLLAddr,
)

# Configurable thresholds
LCP_OVERSIZED_THRESHOLD = 512         # bytes: suspiciously large LCP payload
PPPOE_DISCOVERY_LEN_THRESHOLD = 200   # bytes: PPPoE discovery payload unusually long
ICMPV6_ECHO_RATE_WINDOW = 10         # seconds
ICMPV6_ECHO_RATE_THRESHOLD = 200     # # of ICMPv6 echo reqs in window (suspicious)
ND_RATE_WINDOW = 10                   # seconds
ND_RATE_THRESHOLD = 100               # # of ND NS/NA in window (suspicious)
ALERT_COOLDOWN = 30.0                # seconds between alerts for the same key
EVENT_RETENTION = 60                 # seconds for event history

# Auto-block defaults
DEFAULT_BLOCK_TIME = 600             # seconds rules stay in place (if auto-block enabled)
FIREWALL_BACKEND = 'nft'             # try 'nft', fallback to 'ip6tables'

# Logging setup
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('pppoe_protector')

# Rate trackers
class RateTracker:
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.events: Deque[float] = deque()

    def add(self, ts: Optional[float] = None):
        now = ts if ts is not None else time.time()
        self.events.append(now)
        self._evict(now)

    def count(self) -> int:
        self._evict(time.time())
        return len(self.events)

    def _evict(self, now: float):
        while self.events and (now - self.events[0]) > self.window:
            self.events.popleft()

# global trackers keyed by source (MAC or IPv6)
pppoe_discovery_tracker: Dict[str, RateTracker] = defaultdict(lambda: RateTracker(10))
icmpv6_echo_tracker: Dict[str, RateTracker] = defaultdict(lambda: RateTracker(ICMPV6_ECHO_RATE_WINDOW))
nd_tracker: Dict[str, RateTracker] = defaultdict(lambda: RateTracker(ND_RATE_WINDOW))
recent_alerts: Dict[str, float] = {}  # key -> last alert time

# Firewall management
class FirewallBackend:
    backend: str

    def __init__(self, prefer: str = 'nft'):
        self.backend = prefer if self._check_backend(prefer) else self._auto_detect()
        logger.info("Firewall backend selected: %s", self.backend)

    def _check_backend(self, name: str) -> bool:
        try:
            if name == 'nft':
                subprocess.run(['nft', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif name == 'ip6tables':
                subprocess.run(['ip6tables', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                return False
            return True
        except FileNotFoundError:
            return False

    def _auto_detect(self) -> str:
        if self._check_backend('nft'):
            return 'nft'
        if self._check_backend('ip6tables'):
            return 'ip6tables'
        raise RuntimeError("No supported firewall backend found (nft or ip6tables)")

    def add_block_rule(self, src_mac: Optional[str], src_ip: Optional[str], duration: int) -> bool:
        """
        Add a temporary blocking rule. Returns True on success.
        """
        if self.backend == 'nft':
            return self._nft_add(src_mac, src_ip, duration)
        else:
            return self._ipt6_add(src_mac, src_ip, duration)

    def _nft_add(self, src_mac: Optional[str], src_ip: Optional[str], duration: int) -> bool:
        # Create a table and chain if not exists, then add a rule. Use a unique comment with timestamp.
        table = "inet pppoe_protector"
        chain = "input"
        ts = int(time.time())
        comment = f"pppoe_protector:{ts}"
        try:
            # Ensure table exists
            subprocess.run(['nft', 'add', 'table', 'inet', 'pppoe_protector'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Ensure chain exists
            subprocess.run(['nft', 'add', 'chain', 'inet', 'pppoe_protector', 'input', '{ type filter hook input priority 0; }'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Build rule parts
            rule_parts = ['nft', 'add', 'rule', 'inet', 'pppoe_protector', 'input']
            if src_mac:
                rule_parts += ['ether', 'saddr', src_mac, 'counter', 'drop', 'comment', comment]
            elif src_ip:
                # ip6 saddr must be used for IPv6
                rule_parts += ['ip6', 'saddr', src_ip, 'counter', 'drop', 'comment', comment]
            else:
                # generic drop
                rule_parts += ['counter', 'drop', 'comment', comment]
            subprocess.run(rule_parts, check=True, stdout=subprocess.DEVNULL)
            # register expiry so caller can remove later
            _RuleExpiryManager.register_rule(self.backend, comment, duration)
            logger.info("nft rule added (%s) blocking %s %s", comment, src_mac or '', src_ip or '')
            return True
        except subprocess.CalledProcessError as e:
            logger.exception("Failed to add nft rule: %s", e)
            return False

    def _ipt6_add(self, src_mac: Optional[str], src_ip: Optional[str], duration: int) -> bool:
        # ip6tables can't filter on MAC on input for IPv6; fallback to drop by src IP if present
        ts = int(time.time())
        comment = f"pppoe_protector:{ts}"
        try:
            if src_ip:
                cmd = ['ip6tables', '-I', 'INPUT', '-s', src_ip, '-j', 'DROP']
                subprocess.run(cmd, check=True)
                _RuleExpiryManager.register_rule(self.backend, comment, duration, extra={'cmd': cmd})
                logger.info("ip6tables rule added (%s) blocking %s", comment, src_ip)
                return True
            else:
                logger.warning("ip6tables backend: can't block by MAC for IPv6; skipping")
                return False
        except subprocess.CalledProcessError as e:
            logger.exception("Failed to add ip6tables rule: %s", e)
            return False


# Rule expiry manager
class _RuleExpiryManager:
    """
    Tracks firewall rules we create (by comment) and removes them after expiry.
    For nft, we use comment text to find and delete the rule. For ip6tables we stored the exact cmd to remove.
    """
    _lock = threading.Lock()
    _rules: Dict[str, Tuple[str, float, Optional[dict]]] = {}  # comment -> (backend, expiry_ts, optional meta)

    @classmethod
    def register_rule(cls, backend: str, comment: str, ttl: int, extra: Optional[dict] = None):
        with cls._lock:
            expiry = time.time() + ttl
            cls._rules[comment] = (backend, expiry, extra)
            logger.debug("Registered rule %s backend=%s expires=%d", comment, backend, int(expiry))

    @classmethod
    def _cleanup_loop(cls):
        while True:
            time.sleep(5)
            now = time.time()
            remove = []
            with cls._lock:
                for comment, (backend, expiry, meta) in list(cls._rules.items()):
                    if now >= expiry:
                        remove.append((comment, backend, meta))
                        del cls._rules[comment]
            for comment, backend, meta in remove:
                try:
                    if backend == 'nft':
                        # delete nft rule(s) matching the comment
                        subprocess.run(['nft', 'delete', 'rule', 'inet', 'pppoe_protector', 'input', 'comment', comment], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        logger.info("Removed nft rule with comment %s", comment)
                    elif backend == 'ip6tables' and meta and 'cmd' in meta:
                        # remove by reversing the insertion
                        # best-effort: remove matching rule using exact command stored
                        cmd = meta['cmd']
                        # Build delete version by replacing -I with -D if present
                        dcmd = ['ip6tables'] + ['-D' if x == '-I' else x for x in cmd[1:]]
                        subprocess.run(dcmd, check=False)
                        logger.info("Removed ip6tables rule for %s", comment)
                except Exception:
                    logger.exception("Error removing firewall rule %s", comment)

# start expiry thread
expiry_thread = threading.Thread(target=_RuleExpiryManager._cleanup_loop, daemon=True)
expiry_thread.start()

# Alerting helpers
def should_alert(key: str) -> bool:
    now = time.time()
    last = recent_alerts.get(key, 0)
    if (now - last) > ALERT_COOLDOWN:
        recent_alerts[key] = now
        return True
    return False

# Packet inspection
def inspect_packet(pkt, fw: Optional[FirewallBackend], auto_block: bool, block_time: int):
    try:
        # PPPoE discovery messages
        if pkt.haslayer(PPPoED):
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
            key = f"pppoe_disc:{src_mac}"
            pppoe_discovery_tracker[src_mac].add()
            cnt = pppoe_discovery_tracker[src_mac].count()
            # large raw PPPoED size
            raw_len = len(bytes(pkt[PPPoED])) if pkt.haslayer(PPPoED) else 0
            if raw_len > PPPOE_DISCOVERY_LEN_THRESHOLD and should_alert(key + ":oversize"):
                logger.warning("Large PPPoE discovery payload from %s (len=%d)", src_mac, raw_len)
                if auto_block and fw:
                    fw.add_block_rule(src_mac=src_mac, src_ip=None, duration=block_time)
            if cnt > 200 and should_alert(key + ":rate"):
                logger.warning("High PPPoE discovery rate from %s: %d events", src_mac, cnt)
                if auto_block and fw:
                    fw.add_block_rule(src_mac=src_mac, src_ip=None, duration=block_time)

        # PPP session LCP checks
        if pkt.haslayer(PPPoE) and pkt.haslayer(PPP) and pkt.haslayer(PPP_LCP):
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
            raw_lcp_len = len(bytes(pkt[PPP_LCP])) if pkt.haslayer(PPP_LCP) else 0
            if raw_lcp_len > LCP_OVERSIZED_THRESHOLD and should_alert(f"lcp_oversize:{src_mac}"):
                logger.warning("Oversized PPP LCP from %s (len=%d) - suspicious configure", src_mac, raw_lcp_len)
                if auto_block and fw:
                    fw.add_block_rule(src_mac=src_mac, src_ip=None, duration=block_time)

        # ICMPv6 Echo flood detection
        if pkt.haslayer(ICMPv6EchoRequest):
            src_ip = pkt[IPv6].src if pkt.haslayer(IPv6) else 'unknown'
            icmpv6_echo_tracker[src_ip].add()
            cnt = icmpv6_echo_tracker[src_ip].count()
            if cnt > ICMPV6_ECHO_RATE_THRESHOLD and should_alert(f"icmpv6_echo:{src_ip}"):
                logger.warning("ICMPv6 echo flood from %s: %d pkts in %ds", src_ip, cnt, ICMPV6_ECHO_RATE_WINDOW)
                if auto_block and fw:
                    fw.add_block_rule(src_mac=None, src_ip=src_ip, duration=block_time)

        # Neighbor discovery (NS/NA) checks
        if pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
            src_ip = pkt[IPv6].src if pkt.haslayer(IPv6) else 'unknown'
            nd_tracker[src_ip].add()
            cnt = nd_tracker[src_ip].count()
            if cnt > ND_RATE_THRESHOLD and should_alert(f"nd_rate:{src_ip}"):
                logger.warning("High ND (NS/NA) rate from %s: %d in %ds", src_ip, cnt, ND_RATE_WINDOW)
                if auto_block and fw:
                    fw.add_block_rule(src_mac=None, src_ip=src_ip, duration=block_time)
            # Check ND link-layer address options for unusually long values
            for opt in (pkt.getlayer(ICMPv6NDOptSrcLLAddr, None), pkt.getlayer(ICMPv6NDOptDstLLAddr, None)):
                if opt is None:
                    continue
                try:
                    ll = getattr(opt, 'lladdr', None)
                    if ll and len(ll) > 32 and should_alert(f"nd_ll_long:{src_ip}"):
                        logger.warning("ND option contains long LL address from %s len=%d", src_ip, len(ll))
                        if auto_block and fw:
                            fw.add_block_rule(src_mac=None, src_ip=src_ip, duration=block_time)
                except Exception:
                    pass

    except Exception as e:
        logger.exception("Error inspecting packet: %s", e)



# Sniffer harness
def run_sniffer(iface: str, auto_block: bool, block_time: int, pcap: Optional[str]):
    fw = None
    if auto_block:
        try:
            fw = FirewallBackend(FIREWALL_BACKEND)
        except Exception as e:
            logger.exception("Auto-block requested but no firewall backend available: %s", e)
            fw = None
            logger.warning("Continuing in alert-only mode.")

    logger.info("Starting sniffer on iface=%s (auto_block=%s)", iface, bool(fw))
    bpf = "(pppoed || pppoes || ip6) and not arp"
    if pcap:
        # read from pcap file, no filter param in that mode with scapy's sniff reading file
        logger.info("Reading packets from PCAP: %s", pcap)
        sniff(offline=pcap, prn=lambda pkt: inspect_packet(pkt, fw, auto_block and fw is not None, block_time), store=False)
    else:
        sniff(iface=iface, prn=lambda pkt: inspect_packet(pkt, fw, auto_block and fw is not None, block_time), store=False, filter=bpf)



# CLI parsing
def parse_args():
    p = argparse.ArgumentParser(description="PPPoE/IPv6 protector (defensive).")
    p.add_argument("--iface", "-i", required=True, help="Network interface to listen on (must see target traffic).")
    p.add_argument("--auto-block", action="store_true", help="Enable automatic blocking via firewall (nft or ip6tables).")
    p.add_argument("--block-time", type=int, default=DEFAULT_BLOCK_TIME, help="Auto-block duration (seconds).")
    p.add_argument("--pcap", help="Optional PCAP file to read instead of live capture (useful for tuning).")
    p.add_argument("--debug", action="store_true", help="Enable debug logging.")
    return p.parse_args()


# Entrypoint
def main():
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    logger.info("pppoe_protector starting; iface=%s auto_block=%s", args.iface, args.auto_block)
    try:
        run_sniffer(args.iface, args.auto_block, args.block_time, args.pcap)
    except KeyboardInterrupt:
        logger.info("Shutting down (user interrupt).")
    except Exception as e:
        logger.exception("Fatal error: %s", e)

if __name__ == "__main__":
    main()
