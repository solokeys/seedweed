"""Seeded WebAuthn Credentials: reference implementation"""

__version__ = "1.0rc5"

from . import conformance, reference, vectors  # noqa: F401
from .reference import *  # noqa: F401,F403


def load_test_vectors(shortlist=False):
    return vectors.load(shortlist)
