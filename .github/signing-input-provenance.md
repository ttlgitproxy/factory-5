# Temporary signing input provenance diagnostic

This observer is diagnostic preparation, not a signing fix. The owner decides
when to land and run it, after the separate app-configuration re-saving experiment.
Do not change the signing pair, password, or signing settings as part of enabling
this observer.

Before the first owner-authorized run containing this step, the owner must
privately configure these GitHub Actions secrets from the exact unchanged local
file pair that previously printed `MATCH`:

| Secret | Expected value |
| --- | --- |
| `DIAGNOSTIC_EXPECTED_P12_SHA256` | SHA-256 of the complete original P12 file bytes |
| `DIAGNOSTIC_EXPECTED_PROFILE_SHA256` | SHA-256 of the complete original provisioning profile file bytes |

Use 64 hexadecimal characters, not a filename, command output line, Base64 text,
certificate fingerprint, or a digest of decoded certificate data. Hex case and
surrounding whitespace are normalized. Keep both values private: do not put them
in commits, tickets, comments, logs, or artifacts.

After successful profile import, the observer reads `CERTIFICATE_PATH` and
`PROFILE_PATH` as opaque bytes. It never opens a private key or decodes a
certificate/profile, and does not modify the input files. Successful observation
prints only:

```text
INPUT_PROVENANCE_STATUS=compared
P12_FILE_MATCH=yes
PROFILE_FILE_MATCH=yes
```

Either match field may be `no`. All four yes/no combinations exit successfully
and allow the unchanged identity/profile membership gate to run. `yes` means
byte-for-byte agreement with the owner's expected digest, not valid signing
credentials. `no` means different bytes, not necessarily an invalid credential.
For example, re-exporting a P12 can change its bytes without changing its identity.
The existing `VALID_IDENTITY_COUNT`, `SIGNING_VALIDATION_STATUS`, and
`P12_PROFILE_MATCH` outputs remain the signing decision.

An observation error instead emits one non-sensitive GitHub error annotation,
`INPUT_PROVENANCE_ERROR=<category>`, and exits nonzero without partial match
results. Categories use `p12` or `profile` in place of `<input>`:

| Category | Meaning |
| --- | --- |
| `expected_<input>_missing` | Expected hash is unset, empty, or whitespace-only |
| `expected_<input>_invalid` | Expected hash is not exactly 64 hexadecimal characters |
| `<input>_path_missing` | Runtime path environment variable is unset or empty |
| `<input>_path_invalid` | Runtime path cannot be used as a filesystem path |
| `<input>_file_missing` | Input file (or a parent directory) does not exist |
| `<input>_file_unreadable` | File cannot be read completely, including directory inputs |

These errors mean the diagnostic could not compare inputs; they are not hash
mismatches or evidence of invalid credentials. Expected/actual hashes, input
values, OS error messages, private paths, and file contents are never printed.
Existing signing-input masking is unchanged; do not enable shell tracing.

The proxy workflows do not publish private build caches or deployment-log
artifacts. Private-source quality-gate output is suppressed, and deployment
excerpts are masked before being passed between steps for private status
reporting. Logs remain transient runner files and are removed with the source
checkout.

## Local synthetic regression coverage

No signing files, credentials, external packages, or Apple tooling are needed:

```sh
python3 -B -m unittest discover -s .github/tests -p test_signing_input_provenance.py -v
```

The tests execute the runner helper with synthetic files for all match
combinations, normalization, malformed/missing inputs, complete binary reads,
and exact output boundaries. Permission/read failures are also injected at the
filesystem boundary for consistent coverage on Windows and privileged hosts.

Remove the temporary workflow step, its sparse-checkout entry, helper, tests,
this document, and the two diagnostic secrets when the owner ends the experiment.
