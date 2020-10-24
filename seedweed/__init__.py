"""Seeded WebAuthn Credentials: reference implementation"""

__version__ = "1.0-pre"

from . import conformance, vectors
from .reference import *


def load_test_vectors():
    return vectors.load()
