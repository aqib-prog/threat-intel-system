# Windows structured-field pilot (Card 5, Part 1, step 7)

This offline compiler reloads the approved Windows candidates from the pinned
Sigma checkout and serializes pySigma's field-aware condition trees as plain
Python data. The running application does not depend on pySigma.

The hybrid policy is field-authoritative: complete JSON records use structured
evaluation even when a field is absent (known absence); partial KV/Event Viewer
records use structured evaluation once a full positive field branch is
available, and otherwise retain raw-regex fallback. Rules without a supported
structured tree remain untouched.

```bash
SIGMA_ROOT=/private/tmp/card5-sigma \
  backend/venv/bin/python tools/windows_structured/compiler.py \
  --sigma-root /private/tmp/card5-sigma
```
