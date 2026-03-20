from fastapi.testclient import TestClient

import main
from spam_memory import reset_memory
from safe_circle import reset_history
from user_habits import reset_habits


client = TestClient(main.app)


def test_phishing_input_classifies():
    main.ALERTS.clear()
    reset_memory()
    reset_habits()
    resp = client.post(
        "/analyze",
        json={
            "text": "Your bank account will be blocked. Click here now!",
            "elderly_mode": False,
            "user_id": "test-user-1",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["Threat"] == "phishing"
    assert data["Trust Score"].endswith("%")
    assert isinstance(data["Actions"], list)


def test_empty_input_rejected():
    main.ALERTS.clear()
    reset_memory()
    reset_habits()
    resp = client.post("/analyze", json={"text": "   "})
    assert resp.status_code == 400
    data = resp.json()
    assert "detail" in data


def test_alerts_endpoint_filters_and_returns():
    main.ALERTS.clear()
    reset_memory()
    reset_habits()
    _ = client.post(
        "/analyze",
        json={"text": "click here to verify your account", "user_id": "test-user-2"},
    )
    resp = client.get("/alerts?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert "message" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_spam_memory_influences_second_similar_message():
    main.ALERTS.clear()
    reset_memory()
    reset_habits()

    msg1 = "URGENT: You have won a prize. Claim it now via gift card."
    msg2 = "You have won a prize. Claim it now via gift card urgently!"

    resp1 = client.post("/analyze", json={"text": msg1, "user_id": "test-user-3"})
    assert resp1.status_code == 200

    resp2 = client.post("/analyze", json={"text": msg2, "user_id": "test-user-3"})
    assert resp2.status_code == 200
    data2 = resp2.json()

    # On the second similar message, we should explain that patterns matched
    # against previously detected suspicious content.
    explanation = data2.get("Explanation") or []
    assert any("spam memory" in str(x).lower() for x in explanation)


def test_safe_circle_share_and_receive():
    main.ALERTS.clear()
    reset_memory()
    reset_history()
    reset_habits()

    share_resp = client.post(
        "/safe-circle/share",
        json={
            "status_text": "Need help verifying my account activity.",
            "passphrase": "guard1234",
        },
    )
    assert share_resp.status_code == 200
    share_code = share_resp.json().get("share_code")
    assert share_code

    recv_resp = client.post(
        "/safe-circle/receive",
        json={"share_code": share_code, "passphrase": "guard1234"},
    )
    assert recv_resp.status_code == 200
    payload = recv_resp.json()
    assert payload["status_text"] == "Need help verifying my account activity."
    assert payload["location"]


def test_safe_circle_receive_wrong_passphrase_fails():
    reset_memory()
    reset_history()
    reset_habits()

    share_resp = client.post(
        "/safe-circle/share",
        json={
            "status_text": "I suspect a phishing email. Please assist.",
            "passphrase": "secret-pass",
        },
    )
    assert share_resp.status_code == 200
    share_code = share_resp.json().get("share_code")

    recv_resp = client.post(
        "/safe-circle/receive",
        json={"share_code": share_code, "passphrase": "wrong-pass"},
    )
    assert recv_resp.status_code == 400


def test_user_habits_unusual_new_location_after_baseline():
    main.ALERTS.clear()
    reset_memory()
    reset_history()
    reset_habits()

    user_id = "habit-user-1"
    base_text = "Your account will be blocked. Click here now!"

    # Baseline: same location 5 times to establish a "preferred" location.
    for _ in range(5):
        resp = client.post(
            "/analyze",
            json={"text": base_text, "user_id": user_id, "location": "Bangalore"},
        )
        assert resp.status_code == 200

    # New location should trigger the habit-based "unusual activity" explanation.
    resp2 = client.post(
        "/analyze",
        json={"text": base_text, "user_id": user_id, "location": "Delhi"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    explanation = data2.get("Explanation") or []
    assert any("Unusual activity detected" in str(x) for x in explanation)
