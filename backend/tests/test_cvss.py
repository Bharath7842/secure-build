"""CVSS v3.1 base scores, checked against scores FIRST and NVD publish."""

import pytest

from app.services import cvss


@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),  # prefix optional
])
def test_base_scores_match_published_values(vector, score):
    assert cvss.base_score(vector) == score


def test_roundup_follows_the_specification_not_float_ceil():
    # 4.000000000000001 must stay 4.0 (a float ceil would give 4.1).
    assert cvss.roundup(4.000000000000001) == 4.0
    assert cvss.roundup(4.02) == 4.1
    assert cvss.roundup(4.0) == 4.0


@pytest.mark.parametrize("score, band", [
    (None, "INFO"), (0.0, "INFO"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL"),
])
def test_bands_are_the_specification_ratings(score, band):
    assert cvss.band(score) == band


def test_with_metrics_rewrites_one_metric_and_normalises_the_vector():
    assert cvss.with_metrics("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", PR="L") == (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    )


@pytest.mark.parametrize("vector", [
    "", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/Q:1",
])
def test_malformed_vectors_are_refused(vector):
    with pytest.raises(cvss.CvssError):
        cvss.parse(vector)
