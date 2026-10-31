"""
tests/test_cdn_profiler.py
Automated Unit Tests for Cloud & CDN Architecture Profiler
"""

from src.features.cdn_profiler import profile_cdn_domain


def test_profile_cdn_domain_cloudfront():
    dom = "d123456abcdef8.cloudfront.net"
    res = profile_cdn_domain(dom)
    assert res["is_cdn"] is True
    assert "CloudFront" in res["cdn_provider"]
    assert res["attenuation_factor"] < 1.0


def test_profile_cdn_domain_akamai():
    dom = "a1873.dscg.akamai.net"
    res = profile_cdn_domain(dom)
    assert res["is_cdn"] is True
    assert "Akamai" in res["cdn_provider"]
    assert res["attenuation_factor"] <= 0.35


def test_profile_cdn_domain_non_cdn_dga():
    dom = "qxa3e3u61mpzga8d3.dga.tk"
    res = profile_cdn_domain(dom)
    assert res["is_cdn"] is False
    assert res["cdn_provider"] is None
    assert res["attenuation_factor"] == 1.0
