"""Seeded WebAuthn Credentials: reference implementation"""

__version__ = "1.0rc3"

from . import conformance, reference, vectors  # noqa: F401
from .reference import *  # noqa: F401,F403


def load_test_vectors():
    return vectors.load()
