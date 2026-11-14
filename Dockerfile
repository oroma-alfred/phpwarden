# phpwarden — PHP vulnerability scanner, findings ranked by real-world
# exploitation (CISA KEV first, then EPSS, then CVSS). The bundled advisory
# feed ships inside the image, so scans run fully offline.
#
#   docker build -t phpwarden .
#   docker run --rm phpwarden scan --version 8.3.10 --sapi fpm --os linux
#   docker run --rm -v "$PWD:/src:ro" phpwarden deps /src/composer.lock --project /src
#   docker run --rm -v /var/www/html:/wp:ro phpwarden wordpress /wp
#   docker run --rm -v "$PWD:/src:ro" phpwarden deps /src/composer.lock \
#       --report-to https://app.phpwarden.io/v1/reports --report-token "$PHPWARDEN_REPORT_TOKEN"
#
# Full usage, including CI and cron: docs/docker.md
FROM python:3.12-slim

LABEL org.opencontainers.image.title="phpwarden" \
      org.opencontainers.image.description="PHP vulnerability scanner: engine/FPM, Composer and WordPress CVEs ranked by real-world exploitation (CISA KEV + EPSS), not CVSS. Offline feed, zero dependencies." \
      org.opencontainers.image.url="https://phpwarden.io" \
      org.opencontainers.image.source="https://github.com/oroma-alfred/phpwarden" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /opt/phpwarden
# pyproject.toml points readme at README.md, so pip needs both.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /opt/phpwarden/src /root/.cache

# Feed cache for `feed update` (free weekly or maintained channel); mount a volume here to keep it.
RUN useradd --system --no-create-home phpwarden && mkdir /feed && chown phpwarden /feed
ENV PHPWARDEN_HOME=/feed
USER phpwarden
WORKDIR /work
ENTRYPOINT ["phpwarden"]
CMD ["--help"]
