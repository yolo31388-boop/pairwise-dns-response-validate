"""DNS 响应校验核心模块。

围绕 DNS 缓存投毒（Kaminsky 类）攻击面的防御原语：

* 事务 ID / 源端口的不可预测性；
* 0x20 （DNS case randomization）编码校验；
* DNSSEC 验证结果判定；
* 丢弃无关附加段记录；
* 缓存写入前的一致性检查；
* 无应答 / 校验失败时的重试与降级策略；
* 审计、错误映射与监控指标。

所有入口均为纯函数，通过 ``(payload, context)`` 形式接收输入并返回
可断言的结果；参数可为 ``dict`` 等映射类型，缺省键一律按“不安全”处理。
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# 内部常量与工具
# ---------------------------------------------------------------------------

#: 一个 DNS 报文头的事务 ID 字段长度（bit）。
TXID_BITS = 16
#: 事务 ID 的取值空间。
TXID_SPACE = 1 << TXID_BITS
#: 源端口最低推荐熵：16 bit 端口空间去除知名端口后的粗略下界。
MIN_PORT_ENTROPY_BITS = 14
#: 0x20 编码下每个字母可独立翻转，单个标签至少要求的随机字母数。
MIN_CASE_LETTERS = 1

#: 应答与问题类型一致时视为“相关”的问题类型（A / AAAA 及常见类型）。
_RELEVANT_QTYPES = frozenset(
    {1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 43, 46, 47, 48, 64, 65, 257}
)

#: 附加段中若出现以下“粘合”类 RR，只有在与问题同区时才算相关。
_GLUE_TYPES = frozenset({1, 28})  # A / AAAA


def _ctx(payload: Any) -> Mapping[str, Any]:
    if isinstance(payload, Mapping):
        return payload
    return {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any) -> bool:
    return bool(value)


def _log2(n: float) -> float:
    import math

    return math.log2(n) if n > 0 else 0.0


def _shannon_entropy(values: list[int]) -> float:
    """对实际观测到的 ID / 端口样本做香农熵估计。"""
    if not values:
        return 0.0
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    total = len(values)
    import math

    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# 1. 事务 ID 随机化
# ---------------------------------------------------------------------------


def txid_random(payload: Any, context: Any = None) -> dict:
    """生成 / 校验事务 ID 的随机性。

    ``payload`` 支持：

    * ``{"txid": 0x1234, "previous": [..]}`` —— 校验单个 ID 是否可预测
      （与前序 ID 相同、连续递增、固定值、全 0 / 全 1 等）；
    * ``{"ids": [..]}`` —— 对历史样本做熵估计；
    * ``{"count": n}`` —— 生成 ``n`` 个新 ID。

    返回值包含 ``ok`` / ``value`` / ``reason`` / ``entropy_bits``。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    prev = [int(x) for x in payload.get("previous", [])] if isinstance(payload.get("previous"), (list, tuple)) else []
    if "ids" in payload and isinstance(payload["ids"], (list, tuple)):
        prev = [int(x) for x in payload["ids"]]

    count = _as_int(payload.get("count", 0))
    txid = payload.get("txid", None)

    if count > 0:
        ids = [secrets.randbelow(TXID_SPACE) for _ in range(count)]
        return {
            "ok": True,
            "values": ids,
            "entropy_bits": TXID_BITS,
            "reason": "generated",
        }

    entropy = _shannon_entropy(prev) if len(prev) > 1 else float(TXID_BITS)
    if txid is not None:
        cur = int(txid) & 0xFFFF
        if prev:
            if cur == prev[-1]:
                return {"ok": False, "value": cur, "reason": "repeated", "entropy_bits": entropy}
            if cur == (prev[-1] + 1) & 0xFFFF:
                return {"ok": False, "value": cur, "reason": "sequential", "entropy_bits": entropy}
        if cur in (0x0000, 0xFFFF):
            return {"ok": False, "value": cur, "reason": "degenerate", "entropy_bits": entropy}
        return {"ok": True, "value": cur, "reason": "random", "entropy_bits": entropy}

    # 默认提供一次新生成结果，便于调用方直接使用。
    value = secrets.randbelow(TXID_SPACE)
    return {"ok": True, "value": value, "entropy_bits": float(TXID_BITS), "reason": "generated"}


# ---------------------------------------------------------------------------
# 2. 源端口随机化
# ---------------------------------------------------------------------------


def source_port(payload: Any, context: Any = None) -> dict:
    """生成 / 校验源端口是否为临时端口且不可预测。

    ``payload`` 支持 ``{"port": 5353, "previous": [..]}``、
    ``{"ports": [..]}`` 或 ``{"count": n}``。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    prev: list[int] = []
    for key in ("previous", "ports"):
        if isinstance(payload.get(key), (list, tuple)):
            prev = [int(x) for x in payload[key]]
            break

    count = _as_int(payload.get("count", 0))
    if count > 0:
        ports = []
        while len(ports) < count:
            p = secrets.randbelow(65536 - 32768) + 32768  # 32768..65535 临时端口
            ports.append(p)
        return {"ok": True, "values": ports, "entropy_bits": 15.0, "reason": "generated"}

    entropy = _shannon_entropy(prev) if len(prev) > 1 else 15.0
    port = payload.get("port", None)
    if port is None:
        value = secrets.randbelow(65536 - 32768) + 32768
        return {"ok": True, "value": value, "entropy_bits": 15.0, "reason": "generated"}

    value = int(port)
    if not (0 < value < 65536):
        return {"ok": False, "value": value, "reason": "out_of_range", "entropy_bits": 0.0}
    if value < 32768:
        return {"ok": False, "value": value, "reason": "privileged_port", "entropy_bits": entropy}
    if value in prev[:-1]:
        return {"ok": False, "value": value, "reason": "reused", "entropy_bits": entropy}
    if prev and value == prev[-1]:
        return {"ok": False, "value": value, "reason": "repeated", "entropy_bits": entropy}
    if entropy < MIN_PORT_ENTROPY_BITS:
        return {"ok": False, "value": value, "reason": "low_entropy", "entropy_bits": entropy}
    return {"ok": True, "value": value, "reason": "random", "entropy_bits": entropy}


# ---------------------------------------------------------------------------
# 3. 0x20 编码（DNS name case randomization）
# ---------------------------------------------------------------------------


def _qname_as_wire(name: str) -> str:
    return name.rstrip(".")


def name_case_check(payload: Any, context: Any = None) -> dict:
    """校验应答中的问题名是否保留了我们发送时的 0x20 大小写。

    典型输入 ``{"sent": "ExAmPlE.CoM", "received": "ExAmPlE.CoM"}``。
    校验同时忽略末尾点号差异，并在发现大小写不匹配、或原问题名中
    没有可随机化的字母时判定为不可信。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    sent = str(payload.get("sent", payload.get("expected", "")))
    received = str(payload.get("received", payload.get("actual", "")))
    sent = _qname_as_wire(sent)
    received = _qname_as_wire(received)

    if not sent:
        return {"ok": False, "reason": "missing_sent"}
    if not received:
        return {"ok": False, "reason": "missing_received"}

    letters = sum(1 for ch in sent if ch.isalpha())
    if letters < MIN_CASE_LETTERS:
        return {"ok": False, "reason": "no_randomizable_letters", "letters": letters}

    if sent != received:
        # 区分大小写不匹配还是完全不同的名字。
        if sent.lower() != received.lower():
            return {"ok": False, "reason": "name_mismatch", "letters": letters}
        return {"ok": False, "reason": "case_mismatch", "letters": letters}

    mixed = any(ch.isupper() for ch in sent) and any(ch.islower() for ch in sent)
    return {
        "ok": True,
        "reason": "case_match",
        "letters": letters,
        "mixed_case": mixed,
        "entropy_bits": float(letters),
    }


def name_case_encode(payload: Any, context: Any = None) -> dict:
    """对问题名做 0x20 随机编码，返回编码后的名字与期望校验信息。"""
    payload = _ctx(payload)
    name = _qname_as_wire(str(payload.get("name", "")))
    if not name:
        return {"ok": False, "reason": "missing_name"}
    out = []
    bits = 0
    for ch in name:
        if ch.isalpha():
            out.append(ch.upper() if secrets.randbelow(2) else ch.lower())
            bits += 1
        else:
            out.append(ch)
    encoded = "".join(out)
    return {"ok": True, "encoded": encoded, "expected": encoded, "entropy_bits": float(bits)}


# ---------------------------------------------------------------------------
# 4. DNSSEC 验证
# ---------------------------------------------------------------------------


def dnssec_verify(payload: Any, context: Any = None) -> dict:
    """根据 RRSIG / DS / DNSKEY 校验结果给出 DNSSEC 判定。

    ``payload`` 关键字段：

    * ``zone_signed`` —— 区是否启用 DNSSEC（``False`` 时按不强制验证处理）；
    * ``signatures`` —— 列表，每项 ``{"valid": bool, "inception": ts,
      "expiration": ts, "key_tag": int, "covered_type": int}``；
    * ``ds_match`` —— DS 与 DNSKEY 是否匹配；
    * ``chain_ok`` —— 信任链是否完整；
    * ``rrsig_present`` —— 应答是否带 RRSIG。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    now = _as_int(payload.get("now", time.time()))
    zone_signed = payload.get("zone_signed", True)
    rrsig_present = _as_bool(payload.get("rrsig_present", False))
    chain_ok = _as_bool(payload.get("chain_ok", True))
    ds_match = payload.get("ds_match", None)
    signatures = payload.get("signatures", [])

    if not zone_signed:
        return {
            "ok": True,
            "secure": False,
            "reason": "zone_unsigned",
            "required": False,
        }

    if not rrsig_present and not signatures:
        return {"ok": False, "secure": False, "reason": "missing_rrsig"}

    if ds_match is False:
        return {"ok": False, "secure": False, "reason": "ds_mismatch"}
    if ds_match is True and not chain_ok:
        return {"ok": False, "secure": False, "reason": "broken_chain"}

    expired = []
    not_yet = []
    valid_sigs = 0
    for sig in signatures:
        if not isinstance(sig, Mapping):
            continue
        if not _as_bool(sig.get("valid", True)):
            continue
        inception = _as_int(sig.get("inception", 0))
        expiration = _as_int(sig.get("expiration", 0))
        if expiration and now > expiration:
            expired.append(sig.get("key_tag"))
            continue
        if inception and now < inception:
            not_yet.append(sig.get("key_tag"))
            continue
        valid_sigs += 1

    if valid_sigs == 0:
        if expired:
            return {"ok": False, "secure": False, "reason": "signature_expired"}
        if not_yet:
            return {"ok": False, "secure": False, "reason": "signature_not_yet_valid"}
        return {"ok": False, "secure": False, "reason": "invalid_signature"}

    return {"ok": True, "secure": True, "reason": "valid", "valid_signatures": valid_sigs}


# ---------------------------------------------------------------------------
# 5. 附加段丢弃
# ---------------------------------------------------------------------------


def additional_drop(payload: Any, context: Any = None) -> dict:
    """过滤与本次问题无关的附加段（Additional）记录。

    ``payload`` 形如 ``{"question": {"name": ..., "qtype": 1},
    "additional": [{"name": ..., "type": ..., "section": ...}]}``。

    仅保留 ``OPT``（41）与指向问题名 / 同区 glue 记录之外的“相关”
    记录；其余（尤其是任意名称的 A/AAAA）一律丢弃。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    q = payload.get("question", {}) or {}
    qname = _qname_as_wire(str(q.get("name", ""))).lower()
    qtype = _as_int(q.get("qtype", 0))
    records = payload.get("additional", []) or []

    kept, dropped = [], []
    for rec in records:
        if not isinstance(rec, Mapping):
            dropped.append(rec)
            continue
        rtype = _as_int(rec.get("type", 0))
        rname = _qname_as_wire(str(rec.get("name", "")))
        section = str(rec.get("section", "additional")).lower()

        if rtype == 41:  # OPT 属于扩展机制，保留
            kept.append(rec)
            continue
        if section not in ("additional", "extra", "ar"):
            dropped.append(rec)
            continue
        if not qname:
            # 无问题信息时宁可不信任任何附加记录。
            dropped.append(rec)
            continue

        same_name = rname.lower() == qname
        same_zone = rname.lower().endswith("." + qname) if qname else False
        relevant_type = rtype == qtype or rtype in _RELEVANT_QTYPES
        if same_name and relevant_type:
            kept.append(rec)
        elif same_zone and rtype in _GLUE_TYPES:
            kept.append(rec)
        else:
            dropped.append(rec)

    return {
        "ok": len(dropped) == 0,
        "kept": kept,
        "dropped": dropped,
        "dropped_count": len(dropped),
        "reason": "clean" if not dropped else "irrelevant_records",
    }


# ---------------------------------------------------------------------------
# 6. 缓存写入前一致性检查
# ---------------------------------------------------------------------------


def cache_guard(payload: Any, context: Any = None) -> dict:
    """在写入 DNS 缓存前做一致性 / 可信性检查。

    检查项：

    * 事务 ID 与源端口是否匹配待处理请求（``txid_matches`` / ``port_matches``）；
    * 应答的问题名 / 类型是否与请求一致；
    * QR 位是否置位（是应答而非查询）；
    * 应答码是否为可缓存（NOERROR / NXDOMAIN）；
    * 是否已有权威段伪造冲突（``authority_conflict``）；
    * ``now`` 是否落在签名的有效区间内（可选）。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    problems: list[str] = []

    if "txid_matches" in payload and not _as_bool(payload["txid_matches"]):
        problems.append("txid_mismatch")
    if "txid_expected" in payload or "txid_received" in payload:
        if _as_int(payload.get("txid_expected")) != _as_int(payload.get("txid_received")):
            problems.append("txid_mismatch")
    if "port_matches" in payload and not _as_bool(payload["port_matches"]):
        problems.append("port_mismatch")
    if "port_expected" in payload or "port_received" in payload:
        if _as_int(payload.get("port_expected")) != _as_int(payload.get("port_received")):
            problems.append("port_mismatch")

    if payload.get("is_response") is False:
        problems.append("not_a_response")
    if _as_int(payload.get("rcode", 0)) not in (0, 3):
        problems.append("uncacheable_rcode")
    if _as_bool(payload.get("authority_conflict", False)):
        problems.append("authority_conflict")
    if _as_bool(payload.get("truncated", False)):
        problems.append("truncated")
    if _as_bool(payload.get("case_mismatch", False)):
        problems.append("case_mismatch")

    # 最小化 TTL 的时间一致性
    ttl = payload.get("ttl", None)
    if ttl is not None:
        ttl_i = _as_int(ttl, -1)
        if ttl_i < 0:
            problems.append("negative_ttl")

    return {
        "ok": not problems,
        "cacheable": not problems,
        "problems": problems,
        "reason": "consistent" if not problems else problems[0],
    }


# ---------------------------------------------------------------------------
# 7. 重试策略
# ---------------------------------------------------------------------------


def retry_policy(payload: Any, context: Any = None) -> dict:
    """请求无应答 / 校验失败时的重试与放弃策略。

    ``payload``：``{"attempt": 1, "max_attempts": 3, "last_error": ...,
    "timeout_ms": 800}``。返回值给出是否重试、下一次超时与退避延迟，
    并对“连续命中失败”给出放弃建议，避免无限重试拖垮解析。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    attempt = max(1, _as_int(payload.get("attempt", 1), 1))
    max_attempts = max(1, _as_int(payload.get("max_attempts", 3), 3))
    timeout_ms = max(1, _as_int(payload.get("timeout_ms", 800), 800))
    last_error = str(payload.get("last_error", ctx.get("last_error", "")))

    # 明确的攻击信号不做盲目重试（重试也可能被投毒），交由上层降级。
    hard_fail = last_error in {"txid_mismatch", "port_mismatch", "case_mismatch", "spoof_detected"}
    if hard_fail:
        return {
            "ok": False,
            "retry": False,
            "attempt": attempt,
            "delay_ms": 0,
            "timeout_ms": timeout_ms,
            "reason": "hard_failure",
        }

    if attempt >= max_attempts:
        return {
            "ok": False,
            "retry": False,
            "attempt": attempt,
            "delay_ms": 0,
            "timeout_ms": timeout_ms,
            "reason": "exhausted",
        }

    delay = min(2 ** (attempt - 1) * 100, 2000)
    return {
        "ok": True,
        "retry": True,
        "attempt": attempt + 1,
        "delay_ms": delay,
        "timeout_ms": timeout_ms,
        "reason": "retry",
    }


# ---------------------------------------------------------------------------
# 8. 综合校验
# ---------------------------------------------------------------------------


def validation(payload: Any, context: Any = None) -> dict:
    """把上述原语串成一次完整的应答校验流水线。

    流水线顺序（任一失败即拒绝）：

    1. 事务 ID / 源端口匹配；
    2. QR 位与问题名一致性；
    3. 0x20 大小写还原；
    4. DNSSEC（区已签名时强制）；
    5. 附加段过滤；
    6. 缓存写入前一致性。

    返回 ``{"ok": bool, "accepted": bool, "checks": {...},
    "dropped": [...], "reason": ...}``。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    checks: dict[str, Any] = {}

    txid_ok = payload.get("txid_matches", True)
    if "txid_expected" in payload or "txid_received" in payload:
        txid_ok = _as_int(payload.get("txid_expected")) == _as_int(payload.get("txid_received"))
    checks["txid"] = {"ok": _as_bool(txid_ok)}
    if not checks["txid"]["ok"]:
        return {"ok": False, "accepted": False, "checks": checks, "dropped": [], "reason": "txid_mismatch"}

    port_ok = payload.get("port_matches", True)
    if "port_expected" in payload or "port_received" in payload:
        port_ok = _as_int(payload.get("port_expected")) == _as_int(payload.get("port_received"))
    checks["source_port"] = {"ok": _as_bool(port_ok)}
    if not checks["source_port"]["ok"]:
        return {"ok": False, "accepted": False, "checks": checks, "dropped": [], "reason": "port_mismatch"}

    if payload.get("is_response") is False:
        checks["qr"] = {"ok": False}
        return {"ok": False, "accepted": False, "checks": checks, "dropped": [], "reason": "not_a_response"}

    case = name_case_check(
        {
            "sent": payload.get("qname_sent", payload.get("sent", "")),
            "received": payload.get("qname_received", payload.get("received", "")),
        }
    )
    checks["name_case"] = case
    if not case["ok"]:
        return {"ok": False, "accepted": False, "checks": checks, "dropped": [], "reason": case["reason"]}

    sec = dnssec_verify(
        {
            "zone_signed": payload.get("zone_signed", True),
            "rrsig_present": payload.get("rrsig_present", False),
            "signatures": payload.get("signatures", []),
            "ds_match": payload.get("ds_match", None),
            "chain_ok": payload.get("chain_ok", True),
            "now": payload.get("now", time.time()),
        }
    )
    checks["dnssec"] = sec
    if not sec["ok"]:
        return {"ok": False, "accepted": False, "checks": checks, "dropped": [], "reason": sec["reason"]}

    dropped = additional_drop(
        {
            "question": payload.get("question", {"name": payload.get("qname_sent", ""), "qtype": payload.get("qtype", 1)}),
            "additional": payload.get("additional", []),
        }
    )
    checks["additional"] = dropped

    guard = cache_guard(payload)
    checks["cache_guard"] = guard
    if not guard["ok"]:
        return {
            "ok": False,
            "accepted": False,
            "checks": checks,
            "dropped": dropped["dropped"],
            "reason": guard["reason"],
        }

    return {
        "ok": True,
        "accepted": True,
        "checks": checks,
        "dropped": dropped["dropped"],
        "reason": "accepted",
    }


# ---------------------------------------------------------------------------
# 9. 审计日志
# ---------------------------------------------------------------------------


def _fingerprint(*parts: Any) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(repr(part).encode("utf-8", "replace"))
        digest.update(b"\x00")
    return digest.hexdigest()[:32]


def audit(payload: Any, context: Any = None) -> dict:
    """生成可审计的校验事件记录（不含敏感载荷原文）。

    ``payload`` 可含 ``event`` / ``qname`` / ``txid`` / ``verdict`` /
    ``reason`` 等字段；返回定长指纹、时间戳与标准化字段。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    event = str(payload.get("event", "dns_response_validate"))
    verdict = str(payload.get("verdict", payload.get("reason", "unknown")))
    qname = str(payload.get("qname", ""))
    txid = payload.get("txid", None)
    port = payload.get("port", None)
    ts = _as_int(payload.get("ts", time.time()), int(time.time()))

    record = {
        "ok": True,
        "event": event,
        "verdict": verdict,
        "ts": ts,
        "qname": qname,
        "txid": None if txid is None else int(txid),
        "port": None if port is None else int(port),
        "fingerprint": _fingerprint(event, verdict, qname, txid, port, ts),
        "level": "warn" if verdict not in ("accepted", "valid", "ok") else "info",
    }
    return record


# ---------------------------------------------------------------------------
# 10. 错误映射
# ---------------------------------------------------------------------------

_ERROR_MAP = {
    "txid_mismatch": {"code": "DNS_E_TXID", "severity": "high", "retryable": False},
    "port_mismatch": {"code": "DNS_E_PORT", "severity": "high", "retryable": False},
    "case_mismatch": {"code": "DNS_E_CASE", "severity": "high", "retryable": False},
    "name_mismatch": {"code": "DNS_E_QNAME", "severity": "high", "retryable": False},
    "missing_rrsig": {"code": "DNS_E_DNSSEC_NOSIG", "severity": "medium", "retryable": True},
    "invalid_signature": {"code": "DNS_E_DNSSEC_SIG", "severity": "high", "retryable": False},
    "signature_expired": {"code": "DNS_E_DNSSEC_EXPIRED", "severity": "medium", "retryable": True},
    "signature_not_yet_valid": {"code": "DNS_E_DNSSEC_NOTYET", "severity": "low", "retryable": True},
    "ds_mismatch": {"code": "DNS_E_DNSSEC_DS", "severity": "high", "retryable": False},
    "broken_chain": {"code": "DNS_E_DNSSEC_CHAIN", "severity": "high", "retryable": False},
    "not_a_response": {"code": "DNS_E_QR", "severity": "medium", "retryable": False},
    "authority_conflict": {"code": "DNS_E_AUTH", "severity": "high", "retryable": False},
    "uncacheable_rcode": {"code": "DNS_E_RCODE", "severity": "low", "retryable": True},
    "truncated": {"code": "DNS_E_TRUNC", "severity": "low", "retryable": True},
    "negative_ttl": {"code": "DNS_E_TTL", "severity": "medium", "retryable": False},
    "timeout": {"code": "DNS_E_TIMEOUT", "severity": "low", "retryable": True},
    "irrelevant_records": {"code": "DNS_E_ADDITIONAL", "severity": "medium", "retryable": False},
}


def error_map(payload: Any, context: Any = None) -> dict:
    """把内部校验结论映射成稳定的错误码 / 严重级别 / 可重试标记。"""
    payload = _ctx(payload)
    ctx = _ctx(context)
    reason = payload.get("reason", payload.get("error", None))
    if isinstance(reason, (list, tuple)):
        reason = reason[0] if reason else None
    if reason is None:
        return {"ok": True, "code": "DNS_OK", "severity": "none", "retryable": False, "message": "no error"}
    key = str(reason)
    entry = _ERROR_MAP.get(key)
    if entry is None:
        return {
            "ok": False,
            "code": "DNS_E_UNKNOWN",
            "severity": "medium",
            "retryable": False,
            "message": key,
        }
    return {
        "ok": False,
        "code": entry["code"],
        "severity": entry["severity"],
        "retryable": entry["retryable"],
        "message": key,
    }


# ---------------------------------------------------------------------------
# 11. TTL 收敛
# ---------------------------------------------------------------------------


def ttl_clamp(payload: Any, context: Any = None) -> dict:
    """把 TTL 收敛到安全区间，并对偏短 / 偏长给出提示。

    ``payload``：``{"ttl": 300, "min_ttl": 30, "max_ttl": 86400}``。
    负值或 0 视为不可缓存。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    ttl = _as_int(payload.get("ttl", 0))
    lo = _as_int(payload.get("min_ttl", 30), 30)
    hi = _as_int(payload.get("max_ttl", 86400), 86400)
    lo = max(0, lo)
    hi = max(lo, hi)

    if ttl <= 0:
        return {"ok": False, "ttl": 0, "cacheable": False, "reason": "zero_ttl"}

    clamped = min(max(ttl, lo), hi)
    return {
        "ok": True,
        "ttl": clamped,
        "original": ttl,
        "cacheable": True,
        "clamped": clamped != ttl,
        "reason": "clamped" if clamped != ttl else "within_bounds",
    }


# ---------------------------------------------------------------------------
# 12. 解析器绑定
# ---------------------------------------------------------------------------


def resolver_bind(payload: Any, context: Any = None) -> dict:
    """为出站查询选择并绑定随机化的本地源端口 / 地址。

    ``payload``：``{"udp": true, "tcp": false, "source_ip": "..."}``。
    TCP 查询无需端口随机化（连接由内核四元组保护），但仍需事务 ID。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    udp = _as_bool(payload.get("udp", True))
    tcp = _as_bool(payload.get("tcp", False))
    randomize_port = udp and not tcp

    bind = {"udp": udp, "tcp": tcp, "randomize_port": randomize_port}
    if randomize_port:
        bind["source_port"] = source_port({"count": 1})["values"][0]
    if payload.get("source_ip"):
        bind["source_ip"] = str(payload["source_ip"])
    bind["ok"] = True
    bind["reason"] = "udp_bound" if randomize_port else "tcp_or_passive"
    return bind


# ---------------------------------------------------------------------------
# 13. 监控指标
# ---------------------------------------------------------------------------


def monitoring(payload: Any, context: Any = None) -> dict:
    """汇总校验流水线的运行指标并给出健康度。

    ``payload`` 可含 ``total`` / ``accepted`` / ``rejected`` /
    ``txid_mismatch`` / ``port_mismatch`` / ``case_mismatch`` /
    ``timeouts`` 等累计计数。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    total = max(0, _as_int(payload.get("total", 0)))
    accepted = max(0, _as_int(payload.get("accepted", 0)))
    rejected = max(0, _as_int(payload.get("rejected", total - accepted)))
    suspicious = sum(
        max(0, _as_int(payload.get(k, 0)))
        for k in ("txid_mismatch", "port_mismatch", "case_mismatch", "spoof_detected")
    )
    timeouts = max(0, _as_int(payload.get("timeouts", 0)))

    denom = total if total else 1
    accept_rate = accepted / denom
    suspicious_rate = suspicious / denom
    timeout_rate = timeouts / denom

    if suspicious_rate >= 0.05:
        status = "critical"
    elif suspicious_rate >= 0.01 or timeout_rate >= 0.05:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "ok": status != "critical",
        "status": status,
        "total": total,
        "accepted": accepted,
        "rejected": rejected,
        "suspicious": suspicious,
        "timeouts": timeouts,
        "accept_rate": round(accept_rate, 4),
        "suspicious_rate": round(suspicious_rate, 4),
        "timeout_rate": round(timeout_rate, 4),
    }


# ---------------------------------------------------------------------------
# 14. 降级
# ---------------------------------------------------------------------------


def fallback(payload: Any, context: Any = None) -> dict:
    """在校验失败时决定降级路径。

    ``payload``：``{"reason": ..., "allow_insecure": bool,
    "cached": bool, "have_cache": bool}``。

    * 明确被投毒迹象：拒绝，不使用缓存，不回退明文；
    * 仅超时 / 可重试错误：若允许，回退到已缓存数据或明文解析，并标记
      ``insecure=True``。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    reason = str(payload.get("reason", "timeout"))
    allow_insecure = _as_bool(payload.get("allow_insecure", False))
    have_cache = _as_bool(payload.get("have_cache", payload.get("cached", False)))

    hard = reason in {"txid_mismatch", "port_mismatch", "case_mismatch", "spoof_detected", "authority_conflict"}
    if hard:
        return {
            "ok": False,
            "action": "reject",
            "use_cache": False,
            "insecure": False,
            "reason": "spoof_suspected",
        }

    if allow_insecure:
        if have_cache:
            return {"ok": True, "action": "serve_stale", "use_cache": True, "insecure": True, "reason": "stale_cache"}
        return {"ok": True, "action": "plaintext", "use_cache": False, "insecure": True, "reason": "insecure_fallback"}

    return {"ok": False, "action": "fail", "use_cache": False, "insecure": False, "reason": "no_fallback_allowed"}


# ---------------------------------------------------------------------------
# 15. 欺骗检测
# ---------------------------------------------------------------------------


def spoof_detect(payload: Any, context: Any = None) -> dict:
    """对单个 / 一组应答打分，识别疑似投毒的特征组合。

    评分要素：事务 ID 不匹配、端口不匹配、大小写被改写、附加段含无关
    记录、应答码异常、重复到达的应答（同一 ID 多个不同答案）。
    """
    payload = _ctx(payload)
    ctx = _ctx(context)
    score = 0
    signals: list[str] = []

    if payload.get("txid_matches") is False or (
        "txid_expected" in payload
        and _as_int(payload.get("txid_expected")) != _as_int(payload.get("txid_received"))
    ):
        score += 40
        signals.append("txid_mismatch")
    if payload.get("port_matches") is False or (
        "port_expected" in payload
        and _as_int(payload.get("port_expected")) != _as_int(payload.get("port_received"))
    ):
        score += 25
        signals.append("port_mismatch")
    if _as_bool(payload.get("case_mismatch", False)):
        score += 20
        signals.append("case_mismatch")
    if _as_bool(payload.get("unrelated_additional", False)):
        score += 10
        signals.append("unrelated_additional")
    if _as_bool(payload.get("authority_conflict", False)):
        score += 20
        signals.append("authority_conflict")
    if _as_int(payload.get("duplicate_answers", 0)) > 1:
        score += 15
        signals.append("duplicate_answers")
    if payload.get("is_response") is False:
        score += 15
        signals.append("not_a_response")

    score = min(score, 100)
    if score >= 50:
        level = "spoofed"
    elif score >= 20:
        level = "suspicious"
    else:
        level = "clean"

    return {
        "ok": level == "clean",
        "level": level,
        "score": score,
        "signals": signals,
        "action": "reject" if level == "spoofed" else ("quarantine" if level == "suspicious" else "accept"),
    }
