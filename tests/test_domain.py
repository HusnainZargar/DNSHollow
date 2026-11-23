from manager.engine.domain import is_trusted, split_domain


def test_simple():
    p = split_domain("www.google.com")
    assert (p.parent, p.subdomain, p.depth) == ("google.com", "www", 1)


def test_multi_part_suffix():
    p = split_domain("a.b.example.co.uk")
    assert p.parent == "example.co.uk"
    assert p.subdomain == "a.b"
    assert p.depth == 2


def test_trailing_dot_and_case():
    assert split_domain("WWW.Google.COM.").parent == "google.com"


def test_bare_parent_has_no_subdomain():
    p = split_domain("example.com")
    assert p.subdomain == "" and p.depth == 0


def test_unknown_tld_falls_back_to_last_two_labels():
    p = split_domain("x.y.attacker.tunnel")
    assert p.parent == "attacker.tunnel"
    assert p.subdomain == "x.y"


def test_single_label_and_ip():
    assert split_domain("localhost").parent == "localhost"
    assert split_domain("10.0.0.1").parent == "10.0.0.1"


def test_empty():
    assert split_domain("").parent == ""


def test_is_trusted():
    assert is_trusted("corp.example.com", ["example.com"])
    assert is_trusted("example.com", ["example.com"])
    assert not is_trusted("badexample.com", ["example.com"])
    assert not is_trusted("example.com", [])
