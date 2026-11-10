"""Unit tests for the effect model, the ledger and the approval channel (no network, no model)."""
import base64
import threading
import time

import pytest

from wirebound.approvals import Approvals
from wirebound.model import (Rejected, diff, effect_from_postmark, effect_from_proposal, effect_from_smtp,
                             split_address_list, strict_json)
from wirebound.store import Ledger

BASE = {"From": "ops@acme-lab.example", "To": "alice@example.com", "Subject": "Invoice", "TextBody": "Hi Alice"}


def eff(**kw):
    return effect_from_postmark({**BASE, **kw})[0]


# --- canonical effect -----------------------------------------------------------------------------

def test_digest_ignores_case_order_and_display_names():
    a = eff(To="Alice <ALICE@Example.com>, bob@example.org")
    b = eff(To="bob@example.org, alice@example.com")
    assert a.digest() == b.digest()


def test_digest_changes_with_any_recipient():
    assert eff().digest() != eff(Bcc="phan@giftshop.club").digest()
    assert eff().digest() != eff(Cc="phan@giftshop.club").digest()
    assert eff().digest() != eff(ReplyTo="phan@giftshop.club").digest()


def test_digest_changes_with_content_and_attachments():
    att = [{"Name": "r.txt", "ContentType": "text/plain", "Content": base64.b64encode(b"a").decode()}]
    att2 = [{"Name": "r.txt", "ContentType": "text/plain", "Content": base64.b64encode(b"b").decode()}]
    assert eff().digest() != eff(TextBody="Hi Alice, click here").digest()
    assert eff(Attachments=att).digest() != eff(Attachments=att2).digest()


def test_tracking_and_tags_are_recorded_not_digested():
    e, meta = effect_from_postmark({**BASE, "TrackOpens": True, "TrackLinks": "HtmlAndText", "Tag": "x"})
    assert e.digest() == eff().digest() and meta["TrackOpens"] is True


def test_trailing_newlines_and_crlf_are_canonical():
    assert eff(TextBody="Line one\r\nLine two\r\n").digest() == eff(TextBody="Line one\nLine two").digest()


def test_idn_domain_is_punycoded_consistently():
    assert split_address_list("jose@bücher.example") == ["jose@xn--bcher-kva.example"]


# --- strict parsing (fail closed) -----------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"Bcc": '"evil" <phan@giftshop.club>'},          # quoted display name
    {"Bcc": "phan@giftshop.club (comment)"},          # comment syntax
    {"Bcc": "undisclosed: phan@giftshop.club;"},      # group syntax
    {"Bcc": "=?utf-8?q?x?= <phan@giftshop.club>"},    # encoded word
    {"Headers": [{"Name": "Bcc", "Value": "phan@giftshop.club"}]},
    {"Headers": [{"Name": "X-Custom", "Value": "1"}]},
    {"bcc": "phan@giftshop.club"},                     # unknown (case-variant) field
    {"Envelope": {"RcptTo": ["phan@giftshop.club"]}},  # unknown field
    {"To": "alice@example.com@evil.com"},
    {"From": "a@b.example, c@d.example"},
])
def test_ambiguous_messages_are_rejected(bad):
    with pytest.raises(Rejected):
        effect_from_postmark({**BASE, **bad})


def test_duplicate_and_case_colliding_json_keys_are_rejected():
    with pytest.raises(Rejected):
        strict_json(b'{"To":"alice@example.com","To":"phan@giftshop.club"}')
    with pytest.raises(Rejected):
        strict_json(b'{"Bcc":"","BCC":"phan@giftshop.club"}')


def test_smtp_envelope_only_recipient_is_a_bcc():
    data = (b"From: ops@acme-lab.example\r\nTo: alice@example.com\r\nSubject: Invoice\r\n\r\nHi Alice\r\n")
    e = effect_from_smtp("ops@acme-lab.example", ["alice@example.com", "phan@giftshop.club"], data)
    assert e.bcc == ("phan@giftshop.club",)
    assert e.digest() == eff(Bcc="phan@giftshop.club").digest()


def test_smtp_duplicate_headers_rejected():
    data = b"From: ops@acme-lab.example\r\nTo: alice@example.com\r\nTo: phan@giftshop.club\r\nSubject: x\r\n\r\nx"
    with pytest.raises(Rejected):
        effect_from_smtp("ops@acme-lab.example", ["alice@example.com"], data)


def test_diff_names_the_added_recipient():
    out = diff(eff(), eff(Bcc="phan@giftshop.club"))
    assert out == ["bcc: added phan@giftshop.club (not approved)"]


# --- ledger and approvals --------------------------------------------------------------------------

@pytest.fixture()
def approvals(tmp_path):
    return Approvals(Ledger(tmp_path / "l.sqlite"), b"k" * 32)


def proposal():
    return {"from": "ops@acme-lab.example", "to": "alice@example.com", "subject": "Invoice", "text": "Hi Alice"}


def test_approval_is_single_use(approvals):
    p = approvals.propose("s1", proposal())
    assert approvals.approve(p["send_id"], p["digest"], b"k" * 32)["ok"]
    assert approvals.ledger.consume(p["digest"], "s1") == p["send_id"]
    assert approvals.ledger.consume(p["digest"], "s1") is None


def test_approval_is_session_bound(approvals):
    p = approvals.propose("s1", proposal())
    approvals.approve(p["send_id"], p["digest"], b"k" * 32)
    assert approvals.ledger.consume(p["digest"], "other-session") is None
    assert approvals.ledger.consume(p["digest"], "s1") == p["send_id"]


def test_expired_approval_cannot_be_consumed(approvals):
    p = approvals.propose("s1", proposal())
    approvals.approve(p["send_id"], p["digest"], b"k" * 32, ttl=0.05)
    time.sleep(0.1)
    assert approvals.ledger.consume(p["digest"], "s1") is None


@pytest.mark.parametrize("attack", ["forged_key", "swapped_digest", "replay", "after_deny", "unknown_id"])
def test_approval_channel_attacks_are_refused(approvals, attack):
    p = approvals.propose("s1", proposal())
    other = approvals.propose("s1", {**proposal(), "to": "phan@giftshop.club"})
    key = b"k" * 32
    if attack == "forged_key":
        r = approvals.approve(other["send_id"], other["digest"], b"x" * 32)
    elif attack == "swapped_digest":
        r = approvals.approve(other["send_id"], p["digest"], key)
    elif attack == "replay":
        approvals.approve(p["send_id"], p["digest"], key)
        r = approvals.approve(p["send_id"], p["digest"], key)
    elif attack == "after_deny":
        approvals.deny(other["send_id"])
        r = approvals.approve(other["send_id"], other["digest"], key)
    else:
        r = approvals.approve("snd_missing", p["digest"], key)
    assert not r["ok"]


def test_concurrent_consumers_release_one_dispatch(approvals):
    p = approvals.propose("s1", proposal())
    approvals.approve(p["send_id"], p["digest"], b"k" * 32)
    winners = []
    def grab():
        if approvals.ledger.consume(p["digest"], "s1"):
            winners.append(1)
    threads = [threading.Thread(target=grab) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(winners) == 1


def test_card_shows_bcc_and_digest(approvals):
    p = approvals.propose("s1", {**proposal(), "bcc": "audit@acme-lab.example"})
    assert "Bcc:      audit@acme-lab.example" in p["card"] and p["digest"] in p["card"]


def test_proposal_and_wire_effect_digests_agree():
    e1 = effect_from_proposal({**proposal(), "cc": "finance@example.com"})
    e2 = eff(Cc="finance@example.com", MessageStream="outbound", TrackOpens=True)
    assert e1.digest() == e2.digest()
