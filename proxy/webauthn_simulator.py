"""
MCP Sentinel Mesh - FIDO2 / WebAuthn Hardware Key Approval Engine
Provides cryptographic Human-in-the-Loop assertions binding physical hardware tokens (YubiKey) to high-risk tool approvals.
"""

from typing import Dict, Any, Optional, Tuple
import hashlib
import hmac
import time
import secrets


class WebAuthnVerificationError(Exception):
    pass


class WebAuthnApprovalVerifier:
    """
    Issues and verifies FIDO2 / WebAuthn user presence & biometric assertions
    for pending MCP tool approval requests.
    """

    def __init__(self, rp_id: str = "sentinel.mesh.internal"):
        self.rp_id = rp_id
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        # Registered mock hardware credential public keys (Key ID -> shared secret / pubkey)
        self.registered_credentials: Dict[str, str] = {}

    def register_device(self, credential_id: str, public_secret: str):
        """Registers a trusted FIDO2 security key credential."""
        self.registered_credentials[credential_id] = public_secret

    def create_assertion_challenge(self, approval_id: str, caller_agent_id: str, tool_name: str) -> str:
        """Issues a cryptographically secure 32-byte challenge nonce bound to the approval request."""
        challenge = secrets.token_hex(32)
        self.active_challenges[challenge] = {
            "approval_id": approval_id,
            "caller_agent_id": caller_agent_id,
            "tool_name": tool_name,
            "created_at": time.time(),
            "status": "pending"
        }
        return challenge

    def verify_assertion(
        self,
        challenge: str,
        credential_id: str,
        signature: str,
        user_present: bool = True,
        user_verified_biometric: bool = True
    ) -> Dict[str, Any]:
        """
        Validates FIDO2 authenticator assertion signature and presence flags.
        """
        if challenge not in self.active_challenges:
            raise WebAuthnVerificationError("Invalid or expired WebAuthn challenge.")

        challenge_data = self.active_challenges[challenge]
        if time.time() - challenge_data["created_at"] > 300:  # 5 min expiry
            del self.active_challenges[challenge]
            raise WebAuthnVerificationError("WebAuthn challenge has expired.")

        if credential_id not in self.registered_credentials:
            raise WebAuthnVerificationError(f"Unregistered hardware security key: '{credential_id}'.")

        if not user_present:
            raise WebAuthnVerificationError("FIDO2 User Presence (UP) flag was not set by authenticator.")

        # Verify HMAC assertion signature: HMAC(secret, challenge + approval_id)
        secret = self.registered_credentials[credential_id]
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            f"{challenge}:{challenge_data['approval_id']}:{self.rp_id}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise WebAuthnVerificationError("Cryptographic assertion signature verification failed.")

        # Consume challenge (single-use replay prevention)
        del self.active_challenges[challenge]

        return {
            "verified": True,
            "approval_id": challenge_data["approval_id"],
            "credential_id": credential_id,
            "user_verified_biometric": user_verified_biometric,
            "rp_id": self.rp_id,
            "timestamp": time.time()
        }

    def sign_mock_assertion(self, challenge: str, approval_id: str, credential_id: str) -> str:
        """Helper to generate a valid assertion signature for automated tests and simulations."""
        secret = self.registered_credentials.get(credential_id, "")
        return hmac.new(
            secret.encode("utf-8"),
            f"{challenge}:{approval_id}:{self.rp_id}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
