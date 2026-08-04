# Security Policy

Report vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting feature. Do not include customer scan data, credentials, tokens, or production evidence in a public issue.

The current supported line is Version 1.x. Security fixes are applied to the latest release. Secrets belong in environment variables or an external secret manager, never source control. Scanner evidence is redacted, access-controlled, retention-limited, and should be encrypted at rest in production.

Dependencies and external scanner binaries must be pinned, obtained from official sources, signature/checksum verified, and reviewed before upgrades. Run dependency and container scanning in CI. Rotate `SECRET_KEY` and credentials after suspected exposure.

