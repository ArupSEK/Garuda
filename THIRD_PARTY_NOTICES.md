# Third-party scanner notices

Garuda's Docker build retrieves the following pinned upstream components. Each component remains subject to its upstream license, notices, and trademark terms.

| Component | Pinned release or revision | Upstream |
| --- | --- | --- |
| Nmap | Debian distribution package; actual version recorded per scan | https://nmap.org/ |
| Naabu | 2.6.1 | https://github.com/projectdiscovery/naabu |
| ProjectDiscovery httpx | 1.9.0 | https://github.com/projectdiscovery/httpx |
| Nuclei | 3.11.0 | https://github.com/projectdiscovery/nuclei |
| Nuclei templates | 10.4.7 / `83234ce456da3e90dda86dfbc5e605e64a846df3` | https://github.com/projectdiscovery/nuclei-templates |
| dnsx | release 1.3.0 | https://github.com/projectdiscovery/dnsx |
| testssl.sh | 3.2.4 / `97763a411c525720a5f9bd9d2cded416b10f210a` | https://github.com/testssl/testssl.sh |
| ssh-audit | 3.9.0 | https://github.com/jtesta/ssh-audit |
| GoWitness | 3.1.1 | https://github.com/sensepost/gowitness |
| Chromium | Debian package | https://www.chromium.org/ |

Official release checksums are verified for ProjectDiscovery binaries. GoWitness architecture-specific checksums are pinned in the Dockerfile. Source snapshots use immutable Git commit identifiers. See the corresponding distributions included in the image or the upstream repositories for complete license texts and notices.
