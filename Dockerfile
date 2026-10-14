FROM python:3.12-slim AS xray
ARG TARGETARCH
# Latest non-prerelease resolved from official releases/latest on 2026-10-14.
ARG XRAY_VERSION=v26.3.27
COPY download_xray.py /tmp/download_xray.py
RUN python /tmp/download_xray.py --version "$XRAY_VERSION" --arch "$TARGETARCH" --destination /out/xray

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home agent
COPY --from=xray /out/xray /usr/local/bin/xray
COPY probe_agent.py /app/probe_agent.py
COPY verify_xray.py /app/verify_xray.py
RUN python /app/verify_xray.py
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD ["python", "/app/probe_agent.py", "--healthcheck"]
# No inbound public ports. Temp config needs writable /tmp (tmpfs is sufficient).
CMD ["python", "/app/probe_agent.py"]
