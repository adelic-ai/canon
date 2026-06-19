"""Field modifiers — re / cidr / gt|gte|lt|lte / windash (the high-count constructs the audit measured)."""

from detection.sigma_eval import field_matches


def test_re_modifier_is_regex_search():
    assert field_matches("powershell -enc AAAA", "-enc\\s+[A-Za-z0-9]+", {"re"})
    assert not field_matches("powershell -file x", "-enc\\s+[A-Za-z0-9]+", {"re"})
    # case-sensitive by default; |i makes it insensitive
    assert not field_matches("MIMIKATZ", "mimikatz", {"re"})
    assert field_matches("MIMIKATZ", "mimikatz", {"re", "i"})
    assert not field_matches("x", "(", {"re"})                 # invalid regex → no match, not a crash


def test_cidr_modifier():
    assert field_matches("10.0.5.7", "10.0.0.0/8", {"cidr"})
    assert not field_matches("192.168.1.1", "10.0.0.0/8", {"cidr"})
    assert field_matches("10.0.5.7", ["172.16.0.0/12", "10.0.0.0/8"], {"cidr"})   # list = OR
    assert not field_matches("not-an-ip", "10.0.0.0/8", {"cidr"})                  # bad IP → no match


def test_numeric_comparisons():
    assert field_matches(4625, "4624", {"gt"})
    assert field_matches("4624", "4624", {"gte"})
    assert field_matches(10, "20", {"lt"})
    assert not field_matches(20, "10", {"lt"})
    assert not field_matches("x", "10", {"gt"})                # non-numeric → no match


def test_windash_matches_dash_variants():
    # the pattern's '-' matches -, /, en/em dash (CLI flag evasion)
    for variant in ["-enc", "/enc", "–enc", "—enc"]:
        assert field_matches(f"powershell {variant} AAAA", "-enc", {"windash", "contains"}), variant
    assert not field_matches("powershell enc AAAA", "-enc", {"windash", "contains"})   # no dash at all
