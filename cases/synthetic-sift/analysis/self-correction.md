# Self-Correction Log

## Tempting Initial Inference

The process list contains a beacon-like argument, so the agent initially considered asserting data exfiltration and actor attribution.

## Evidence Check

- Available evidence supports suspicious execution and a synthetic known-bad payload hash.
- Available evidence does not include packet capture, proxy logs, destination reputation, transfer volume, or external threat intelligence.

## Correction

- Actor attribution was downgraded to `unsupported`.
- Data exfiltration was downgraded to `needs_artifact`.

## Missing Artifact Request

Request network capture, proxy logs, or endpoint telemetry before asserting exfiltration. Request external threat intelligence before naming a real-world actor.
