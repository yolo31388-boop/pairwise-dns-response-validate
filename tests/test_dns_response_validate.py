import pytest
import security.dns_response_validate as mod

CASES = [
    ("txid_random", (1, 2)),
    ("source_port", (1, 2)),
    ("name_case_check", (1, 2)),
    ("dnssec_verify", (1, 2)),
    ("additional_drop", (1, 2)),
    ("cache_guard", (1, 2)),
    ("retry_policy", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("error_map", (1, 2)),
    ("ttl_clamp", (1, 2)),
    ("resolver_bind", (1, 2)),
    ("monitoring", (1, 2)),
    ("fallback", (1, 2)),
    ("spoof_detect", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
