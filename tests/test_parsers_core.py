"""CEF and syslog header parsing (vendor-neutral), including the brief's edge cases."""

from datetime import UTC, datetime

import pytest

from app.parsers import severity
from app.parsers.cef import parse_cef, parse_extension
from app.parsers.model import ParseError
from app.parsers.syslog import parse_header, split_tag
from app.parsers.vendors import module_for

NOW = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)
generic = module_for("other")


# ------------------------------------------------------------------ CEF header / extension
def test_cef_basic_header():
    r = parse_cef("CEF:0|Acme|Box|1.2|100|Port scan|7|src=1.2.3.4 dst=10.0.0.1")
    assert (r.version, r.vendor, r.product, r.device_version, r.class_id, r.name, r.severity) == (
        "0", "Acme", "Box", "1.2", "100", "Port scan", "7")
    assert r.ext == {"src": "1.2.3.4", "dst": "10.0.0.1"}


def test_cef_escaped_pipe_and_backslash_in_header():
    r = parse_cef(r"CEF:0|Ac\|me|Box\\Pro|1|id|Name with \| pipe|3|msg=x")
    assert r.vendor == "Ac|me" and r.product == "Box\\Pro" and r.name == "Name with | pipe"


def test_cef_values_with_spaces_and_escaped_equals():
    ext = parse_extension(r"msg=user logged in from host a b c request=http://x/?a\=1&b\=2 cs1Label=Rule Name cs1=Allow All")
    assert ext["msg"] == "user logged in from host a b c"
    assert ext["request"] == "http://x/?a=1&b=2"
    assert ext["cs1"] == "Allow All" and ext["cs1Label"] == "Rule Name"


def test_cef_value_escapes():
    ext = parse_extension(r"msg=line1\nline2 path=C:\\temp")
    assert ext["msg"] == "line1\nline2" and ext["path"] == "C:\\temp"


def test_cef_missing_header_fields_is_parse_error():
    with pytest.raises(ParseError, match="7"):
        parse_cef("CEF:0|Acme|Box|1.2")


def test_cef_empty_extension():
    assert parse_cef("CEF:0|A|B|1|id|n|5|").ext == {}


def test_cef_severity_mapping():
    assert [severity.from_cef(str(i)) for i in (0, 3, 4, 6, 7, 8, 9, 10)] == [
        "low", "low", "medium", "medium", "high", "high", "critical", "critical"]
    assert severity.from_cef("Very-High") == "critical" and severity.from_cef("Medium") == "medium"
    assert severity.from_cef("Unknown") == "low" and severity.from_cef("garbage") == "low"


def test_cef_common_keys_and_unmapped_extra():
    line = ("<134>Oct  6 16:00:00 fw1 CEF:0|Acme|FW|1|deny|Blocked|8|src=203.0.113.9 spt=4444 dst=10.1.1.5 dpt=443 "
            "proto=TCP act=deny suser=bob smac=AA-BB-CC-DD-EE-FF in=10 out=20 outcome=Failure cs2Label=Policy cs2=Block bad "
            "rt=1791273600000 customThing=42")
    ev = generic.parse(line, "Asia/Hong_Kong", NOW)
    assert (ev.src_ip, ev.src_port, ev.dst_ip, ev.dst_port, ev.protocol) == ("203.0.113.9", 4444, "10.1.1.5", 443, "tcp")
    assert ev.action == "deny" and ev.user_name == "bob" and ev.src_mac == "aa:bb:cc:dd:ee:ff"
    assert (ev.bytes_in, ev.bytes_out, ev.outcome) == (10, 20, "failure")
    assert ev.severity == "high" and ev.severity_raw == "8" and ev.event_class == "cef:deny"
    assert ev.extra["Policy"] == "Block bad" and ev.extra["customThing"] == "42"
    assert ev.ts == datetime(2026, 10, 6, 8, 0, tzinfo=UTC)  # rt (epoch ms) wins over the syslog header


def test_very_long_line_does_not_break():
    line = "<13>Oct  6 16:00:00 host CEF:0|A|B|1|x|n|1|msg=" + "y" * 20000
    ev = generic.parse(line, "UTC", NOW)
    assert len(ev.message) == 8000


def test_cef_garbage_values_do_not_crash():
    ev = generic.parse("Oct  6 16:00:00 h CEF:0|A|B|1|x|n|1|src=not-an-ip spt=99999 smac=zz in=abc", "UTC", NOW)
    assert ev.src_ip is None and ev.src_port is None and ev.src_mac is None and ev.bytes_in is None


# ------------------------------------------------------------------ syslog headers
def test_rfc3164_local_time_converted_to_utc():
    h = parse_header("<30>Oct  6 16:29:01 host prog[1]: hello", "Asia/Hong_Kong", NOW)
    assert h.ts == datetime(2026, 10, 6, 8, 29, 1, tzinfo=UTC)
    assert (h.facility, h.severity, h.host) == (3, 6, "host")


def test_rfc3164_without_pri_and_zero_padded_day():
    h = parse_header("Oct 06 16:35:08 NW-HK CEF:0|x", "Asia/Hong_Kong", NOW)
    assert h.severity is None and h.host == "NW-HK" and h.msg.startswith("CEF:0")


def test_rfc3164_year_rollover():
    jan = datetime(2027, 1, 1, 0, 5, tzinfo=UTC)
    h = parse_header("<13>Dec 31 23:59:00 host x: y", "UTC", jan)
    assert h.ts.year == 2026


def test_rfc5424():
    h = parse_header('<165>1 2026-10-06T08:00:00.123Z fw01 app 77 ID47 [ex@1 a="b"] the message', "UTC", NOW)
    assert (h.fmt, h.host, h.app, h.procid, h.msgid, h.msg) == ("rfc5424", "fw01", "app", "77", "ID47", "the message")
    assert h.ts == datetime(2026, 10, 6, 8, 0, 0, 123000, tzinfo=UTC) and h.severity == 5


def test_non_syslog_is_parse_error():
    with pytest.raises(ParseError, match="unrecognised"):
        generic.parse("this is not syslog at all", "UTC", NOW)
    with pytest.raises(ParseError, match="PRI"):
        parse_header("<999>Oct  6 16:29:01 host x", "UTC", NOW)


def test_plain_syslog_fallback():
    ev = generic.parse("<27>Oct  6 16:00:00 sw1 lldpd[42]: something happened", "UTC", NOW)
    assert (ev.category, ev.process, ev.severity, ev.severity_raw) == ("system", "lldpd", "high", "err")
    assert ev.message == "something happened" and ev.extra["pid"] == "42"


def test_split_tag_variants():
    assert split_tag("prog[12]: x") == ("prog", "12", "x")
    assert split_tag("/usr/bin/thing[3]: y") == ("/usr/bin/thing", "3", "y")
    assert split_tag("no tag here") == (None, None, "no tag here")


def test_fortinet_devices_use_generic_cef_until_samples_exist():
    ev = module_for("fortinet").parse("<189>Oct  6 16:00:00 fgt CEF:0|Fortinet|Fortigate|v7|0000000013|traffic:forward accept|3|src=10.0.0.5 dst=8.8.8.8 dpt=53 act=accept", "UTC", NOW)
    assert (ev.vendor, ev.src_ip, ev.dst_ip, ev.dst_port, ev.action) == ("other", "10.0.0.5", "8.8.8.8", 53, "accept")
