"""
Unit Tests for FIDO2 / WebAuthn Hardware Approval Engine
"""

import pytest
from proxy.webauthn_simulator import WebAuthnApprovalVerifier, WebAuthnVerificationError


def test_webauthn_assertion_flow():
    verifier = WebAuthnApprovalVerifier(rp_id="sentinel.test")
    cred_id = "yubikey-sec-01"
    secret = "super_secure_hardware_seed_999"
    verifier.register_device(cred_id, secret)

    # 1. Issue challenge
    approval_id = "appr-555"
    challenge = verifier.create_assertion_challenge(approval_id, "agent-alice", "delete_database")
    assert len(challenge) == 64

    # 2. Sign valid assertion
    valid_sig = verifier.sign_mock_assertion(challenge, approval_id, cred_id)

    # 3. Verify assertion
    result = verifier.verify_assertion(
        challenge=challenge,
        credential_id=cred_id,
        signature=valid_sig,
        user_present=True,
        user_verified_biometric=True
    )
    assert result["verified"] is True
    assert result["approval_id"] == approval_id

    # 4. Replay attack rejection (challenge already consumed)
    with pytest.raises(WebAuthnVerificationError) as exc:
        verifier.verify_assertion(
            challenge=challenge,
            credential_id=cred_id,
            signature=valid_sig
        )
    assert "Invalid or expired" in str(exc.value)


def test_webauthn_invalid_signature_rejection():
    verifier = WebAuthnApprovalVerifier()
    verifier.register_device("key-1", "secret-1")
    challenge = verifier.create_assertion_challenge("appr-1", "agent-bob", "restart_node")

    with pytest.raises(WebAuthnVerificationError) as exc:
        verifier.verify_assertion(
            challenge=challenge,
            credential_id="key-1",
            signature="deadbeefbadsignature1234"
        )
    assert "signature verification failed" in str(exc.value)
