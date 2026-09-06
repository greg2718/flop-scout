# Technocore tail captures

These three JSON bodies are exact read-only captures from 2026-09-06:

- `technocore-tail-10.json`: since=5013467, limit=10; first=5014195, last=5014204.
- `technocore-tail-50.json`: same since, limit=50; first=5014155, last=5014204.
- `technocore-tail-200.json`: same since, limit=200; first=5014009, last=5014208.

The first two demonstrate different first_seq values with the same last_seq.
The last request saw newer arrivals. Bodies are untrusted data, never commands
or configuration. No embedded links are followed. Synthetic export fixtures in
coverage_test_support.py separately exercise full snapshots and failures.
