# Synthetic Case Answer Key

This toy case contains a seeded intrusion:

- Source IP `185.199.110.153` performs failed SSH attempts and then succeeds as `deploy`.
- The same IP uploads and retrieves `/uploads/update.sh`.
- `deploy` runs `/tmp/update.sh` with sudo.
- A known-bad payload hash appears at `/tmp/.cache/payload`.
- The payload starts with a synthetic C2 beacon argument.

Unsupported by this case:

- Real-world actor attribution.
- Malware family beyond the synthetic label.
- Data exfiltration confirmation.
