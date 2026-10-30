"""The Qualys-specific error that stops a run sending further requests."""

from __future__ import annotations

from posture.exceptions import AuthenticationError


class CredentialsRejected(AuthenticationError):
    """Qualys refused the user's credentials or account outright (bad
    login, inactive or unregistered account, SecureID), rather than one
    API or module.

    Every API family logs in as the same user, so once one raises this,
    ``QualysCollector`` sends no further requests for the rest of the run:
    no other table can succeed, and every rejected attempt counts towards
    Qualys's failed-login lockout.
    """
