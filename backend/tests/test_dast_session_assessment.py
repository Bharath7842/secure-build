from app.services.dast_session_assessment import assess_session_loss


def test_successful_logout_makes_session_loss_a_true_positive():
    assessment = assess_session_loss(
        [
            "[4/4] Starting crawl...",
            "    POST http://localhost:4200/api/auth/logout  (status 204, )",
            "    [session_lost] Bounced back to a login-shaped page after visiting http://localhost:4200/home",
        ]
    )

    assert assessment is not None
    assert assessment["verdict"] == "true_positive"
    assert assessment["reason_code"] == "logout_succeeded"
    assert assessment["evidence"] == [
        "POST /api/auth/logout returned HTTP 204.",
        "The browser returned to a login-shaped page after /home.",
    ]


def test_application_json_after_navigation_makes_ui_warning_a_false_positive():
    assessment = assess_session_loss(
        [
            "[4/4] Starting crawl...",
            "    GET http://localhost:4200/api/auth/current-user  (status 200, application/json)",
            "    GET http://localhost:4200/api/employees  (status 200, application/json)",
            "    [session_lost] Bounced back to a login-shaped page after visiting http://localhost:4200/employees",
        ]
    )

    assert assessment is not None
    assert assessment["verdict"] == "false_positive"
    assert assessment["reason_code"] == "application_data_succeeded"
    assert assessment["evidence"][0] == "GET /api/employees returned HTTP 200 application/json."


def test_repeated_summary_warning_does_not_replace_the_original_logout_evidence():
    assessment = assess_session_loss(
        [
            "[4/4] Starting crawl...",
            "    POST http://localhost:4200/api/auth/logout  (status 204, )",
            "    [session_lost] Bounced back to a login-shaped page after visiting http://localhost:4200/home",
            "[4/4] Resuming crawl after session recovery...",
            "    GET http://localhost:4200/api/employees  (status 200, application/json)",
            "  Warnings:",
            "    [session_lost] Bounced back to a login-shaped page after visiting http://localhost:4200/home",
        ]
    )

    assert assessment is not None
    assert assessment["verdict"] == "true_positive"
    assert assessment["event_order"] == 3


def test_no_session_loss_claim_returns_no_assessment():
    assert assess_session_loss(["DAST scan complete."]) is None
