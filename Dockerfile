# Tikl container image.
#
# Primarily the SSH channel (works anywhere). MAC-Telnet from a container works
# ONLY on a Linux host started with `--network host --cap-add=NET_RAW` — on
# Docker Desktop (macOS/Windows) the container cannot reach the physical L2
# segment. See DESIGN.md #6.

FROM python:3.13.13-slim-trixie AS builder

RUN pip install --no-cache-dir uv==0.8.22
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv build --wheel --out-dir /dist

FROM python:3.13.13-slim-trixie

# libpcap runtime for MAC-Telnet (Linux host-network only).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

RUN useradd --create-home --uid 10001 tikl
USER tikl

ENTRYPOINT ["tikl"]
CMD ["--help"]
