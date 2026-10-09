import http.client

from backend.checks import analyze_text
from backend.expand import expand_links, expand_one


def fake_web(routes):
    """routes: {(host, path): (status, location)}; records every host contacted."""
    contacted = []

    def head(host, path):
        contacted.append(host)
        if (host, path) not in routes:
            raise OSError("timeout")
        return routes[(host, path)]

    return head, contacted


def test_follows_shortener_but_never_contacts_destination():
    head, contacted = fake_web({("bit.ly", "/abc"): (301, "https://evil-login.xyz/paypal")})
    r = expand_one("https://bit.ly/abc", head)
    assert r == {"short": "https://bit.ly/abc", "final": "https://evil-login.xyz/paypal", "status": "ok"}
    assert contacted == ["bit.ly"]


def test_chained_shorteners():
    head, contacted = fake_web({
        ("bit.ly", "/a"): (301, "https://tinyurl.com/b"),
        ("tinyurl.com", "/b"): (302, "https://example.org/x"),
    })
    assert expand_one("https://bit.ly/a", head)["final"] == "https://example.org/x"
    assert contacted == ["bit.ly", "tinyurl.com"]


def test_redirect_loop_is_capped():
    head, contacted = fake_web({("bit.ly", "/a"): (301, "https://bit.ly/b"), ("bit.ly", "/b"): (301, "https://bit.ly/a")})
    assert expand_one("https://bit.ly/a", head)["status"] == "failed"
    assert len(contacted) == 4


def test_dead_blocked_and_failed():
    head, _ = fake_web({
        ("bit.ly", "/gone"): (404, None),
        ("bit.ly", "/bad"): (301, "https://bit.ly/a/warning?hash=bad"),
        ("tinyurl.com", "/p"): (302, "https://tinyurl.com/preview/p"),
    })
    assert expand_one("https://bit.ly/gone", head)["status"] == "dead"
    assert expand_one("https://bit.ly/bad", head)["status"] == "blocked"
    assert expand_one("https://tinyurl.com/p", head)["status"] == "failed"
    assert expand_one("https://bit.ly/timeout", head)["status"] == "failed"


def test_http_exception_is_a_failure_not_a_crash():
    def head(host, path):
        raise http.client.RemoteDisconnected("nope")

    assert expand_one("https://bit.ly/x", head)["status"] == "failed"


def test_only_shorteners_are_expanded():
    head, contacted = fake_web({})
    assert expand_links(["https://evil.xyz/a", "https://www.paypal.com/"], head) == {}
    assert contacted == []


def offline_expander(routes):
    head, _ = fake_web(routes)
    return lambda urls: expand_links(urls, head)


def rules(text, routes):
    return {f["rule_id"]: f for f in analyze_text(text, expander=offline_expander(routes))["findings"]}


def test_short_link_to_lookalike_is_caught():
    r = rules("PayPal: confirm your account https://bit.ly/pp1", {("bit.ly", "/pp1"): (301, "https://paypa1-secure.com/x")})
    assert "LOOKALIKE_DOMAIN" in r
    assert "paypa1-secure[.]com" in r["LINK_SHORTENER"]["title"]


def test_short_link_to_real_brand_is_not_held_against_it():
    msg = "Your Amazon order shipped. Track it: https://amzn.to/3abc"
    r = analyze_text(msg, expander=offline_expander({("amzn.to", "/3abc"): (301, "https://www.amazon.com/gp/your-orders")}))
    assert r["verdict"] == "looks_ok"
    assert r["expanded"] == [{"short": "amzn[.]to/3abc", "final": "www[.]amazon[.]com", "status": "ok"}]


def test_brand_mismatch_uses_real_destination():
    msg = "Netflix: payment declined, update here https://bit.ly/nf"
    assert "BRAND_LINK_MISMATCH" in rules(msg, {("bit.ly", "/nf"): (301, "https://billing-help-center.com/")})
    assert "BRAND_LINK_MISMATCH" not in rules(msg, {("bit.ly", "/nf"): (301, "https://www.netflix.com/account")})


def test_flagged_short_link_is_dont_click():
    r = analyze_text("hey check this https://bit.ly/bad", expander=offline_expander({("bit.ly", "/bad"): (301, "https://bit.ly/a/warning")}))
    assert r["verdict"] == "dont_click"


def test_failed_expansion_keeps_the_warning():
    r = rules("Netflix: update payment https://bit.ly/x", {})
    assert r["LINK_SHORTENER"]["severity"] == "medium"


def test_brand_words_inside_links_are_not_claims():
    r = analyze_text("hey look https://tinyurl.com/google", expander=offline_expander({}))
    assert "BRAND_LINK_MISMATCH" not in {f["rule_id"] for f in r["findings"]}
