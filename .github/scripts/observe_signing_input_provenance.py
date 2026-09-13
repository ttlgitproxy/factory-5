"""Temporarily compare decoded signing file bytes without disclosing fingerprints."""

import hashlib
import os
from pathlib import Path
import re
import sys


class ProvenanceError(Exception):
    """A non-sensitive diagnostic category, never an input value or OS message."""


def expected_hash(variable, label):
    value = os.environ.get(variable, "").strip()
    if not value:
        raise ProvenanceError(f"expected_{label}_missing")
    if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ProvenanceError(f"expected_{label}_invalid")
    return value.lower()


def file_hash(variable, label):
    path = os.environ.get(variable, "")
    if not path:
        raise ProvenanceError(f"{label}_path_missing")
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        raise ProvenanceError(f"{label}_file_missing") from None
    except OSError:
        raise ProvenanceError(f"{label}_file_unreadable") from None
    except ValueError:
        # An embedded NUL is invalid on all platforms; do not echo the path.
        raise ProvenanceError(f"{label}_path_invalid") from None
    return hashlib.sha256(data).hexdigest()


def main():
    try:
        expected_p12 = expected_hash("DIAGNOSTIC_EXPECTED_P12_SHA256", "p12")
        expected_profile = expected_hash("DIAGNOSTIC_EXPECTED_PROFILE_SHA256", "profile")
        actual_p12 = file_hash("CERTIFICATE_PATH", "p12")
        actual_profile = file_hash("PROFILE_PATH", "profile")
    except ProvenanceError as error:
        print(f"::error::INPUT_PROVENANCE_ERROR={error}", file=sys.stderr)
        return 1

    # Emit no partial comparisons if either input could not be observed.
    print("INPUT_PROVENANCE_STATUS=compared")
    print(f"P12_FILE_MATCH={'yes' if actual_p12 == expected_p12 else 'no'}")
    print(f"PROFILE_FILE_MATCH={'yes' if actual_profile == expected_profile else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
