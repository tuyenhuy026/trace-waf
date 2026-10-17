FROM python:3.11-slim
ARG AIOHTTP_VERSION
RUN python -m pip install --no-cache-dir "aiohttp==${AIOHTTP_VERSION}"
WORKDIR /lab
COPY server.py /lab/server.py
RUN mkdir -p /lab/static && \
    printf 'TRACE_CVE_PUBLIC_OK\n' > /lab/static/public.txt && \
    printf 'TRACE_CVE_2024_23334_SYNTHETIC_MARKER\n' > /lab/trace-only-cve-marker.txt && \
    chmod -R a+rX /lab
USER nobody
EXPOSE 8080
CMD ["python", "/lab/server.py"]
