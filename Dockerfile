FROM debian:bookworm-slim AS scanner-assets
ARG TARGETARCH
ARG HTTPX_VERSION=1.9.0
ARG NUCLEI_VERSION=3.11.0
ARG NAABU_VERSION=2.6.1
ARG DNSX_VERSION=1.3.0
ARG GOWITNESS_VERSION=3.1.1
ARG NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3
ARG TESTSSL_COMMIT=97763a411c525720a5f9bd9d2cded416b10f210a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && \
    rm -rf /var/lib/apt/lists/* && mkdir -p /assets/bin /assets/nuclei-templates /assets/testssl
RUN set -eux; cd /tmp; \
    asset="httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo "${asset}" "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/${asset}"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo checksums.txt "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_checksums.txt"; \
    grep -F "  ${asset}" checksums.txt | sha256sum -c -; \
    unzip -q "${asset}" -d httpx; install -m 0755 httpx/httpx /assets/bin/httpx-pd
RUN set -eux; cd /tmp; \
    asset="nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo "${asset}" "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${asset}"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo checksums.txt "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep -F "  ${asset}" checksums.txt | sha256sum -c -; \
    unzip -q "${asset}" -d nuclei; install -m 0755 nuclei/nuclei /assets/bin/nuclei
RUN set -eux; cd /tmp; \
    asset="naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo "${asset}" "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/${asset}"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo checksums.txt "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu-checksums.txt"; \
    grep -F "  ${asset}" checksums.txt | sha256sum -c -; \
    unzip -q "${asset}" -d naabu; install -m 0755 naabu/naabu /assets/bin/naabu
RUN set -eux; cd /tmp; \
    asset="dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo "${asset}" "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/${asset}"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo checksums.txt "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_checksums.txt"; \
    grep -F "  ${asset}" checksums.txt | sha256sum -c -; \
    unzip -q "${asset}" -d dnsx; install -m 0755 dnsx/dnsx /assets/bin/dnsx
RUN set -eux; cd /tmp; \
    case "${TARGETARCH}" in \
      amd64) checksum="57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517" ;; \
      arm64) checksum="a24284b4df4ea94a34edc55232b5d102555dcd01c73b1eb950ac4e304f753784" ;; \
      *) echo "Unsupported GoWitness architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    asset="gowitness-${GOWITNESS_VERSION}-linux-${TARGETARCH}"; \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo "${asset}" "https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/${asset}"; \
    echo "${checksum}  ${asset}" | sha256sum -c -; install -m 0755 "${asset}" /assets/bin/gowitness
RUN curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo /tmp/nuclei-templates.tar.gz \
    "https://github.com/projectdiscovery/nuclei-templates/archive/${NUCLEI_TEMPLATES_COMMIT}.tar.gz" && \
    tar -xzf /tmp/nuclei-templates.tar.gz --strip-components=1 -C /assets/nuclei-templates && \
    curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 -fsSLo /tmp/testssl.tar.gz \
    "https://github.com/testssl/testssl.sh/archive/${TESTSSL_COMMIT}.tar.gz" && \
    tar -xzf /tmp/testssl.tar.gz --strip-components=1 -C /assets/testssl

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app \
    NUCLEI_TEMPLATES_PATH=/home/scanner/nuclei-templates \
    SCANNER_VERSIONS="nmap=7.95,naabu=2.6.1,httpx=1.9.0,nuclei=3.11.0,nuclei-templates=10.4.7,dnsx-release=1.3.0,testssl.sh=3.2.4,ssh-audit=3.9.0,gowitness=3.1.1"
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash bsdextrautils ca-certificates chromium curl dnsutils fonts-liberation nmap openssl procps && \
    rm -rf /var/lib/apt/lists/* && useradd --create-home --uid 10001 scanner
COPY --from=scanner-assets /assets/bin/ /usr/local/bin/
COPY --from=scanner-assets /assets/nuclei-templates /home/scanner/nuclei-templates
COPY --from=scanner-assets /assets/testssl /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
COPY dashboard ./dashboard
RUN pip install --no-cache-dir .
COPY --chown=scanner:scanner . .
RUN chown scanner:scanner /app
USER scanner
EXPOSE 8000 8501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

