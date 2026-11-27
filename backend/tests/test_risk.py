from app.risk import score_finding


def test_score_combines_cvss_epss_and_kev():
    breakdown = score_finding(severity=4, cvss=9.8, epss=0.9, in_kev=True, criticality=3)

    assert breakdown.cvss_points == 58.8
    assert breakdown.epss_points == 22.5
    assert breakdown.kev_points == 15.0
    assert breakdown.score == 96.3


def test_known_exploited_medium_outranks_unexploited_high():
    exploited_medium = score_finding(severity=2, cvss=6.5, epss=0.7, in_kev=True)
    quiet_high = score_finding(severity=3, cvss=8.1, epss=0.01, in_kev=False)

    assert exploited_medium.score > quiet_high.score


def test_severity_stands_in_when_cvss_is_missing():
    assert score_finding(severity=3, cvss=None, epss=None, in_kev=False).score == 45.0


def test_host_criticality_scales_the_score():
    low = score_finding(severity=3, cvss=7.5, epss=None, in_kev=False, criticality=1).score
    high = score_finding(severity=3, cvss=7.5, epss=None, in_kev=False, criticality=5).score

    assert (low, high) == (36.0, 54.0)


def test_score_is_capped_and_info_is_zero():
    assert score_finding(severity=4, cvss=10.0, epss=1.0, in_kev=True, criticality=5).score == 100.0
    assert score_finding(severity=0, cvss=None, epss=None, in_kev=False).score == 0.0
