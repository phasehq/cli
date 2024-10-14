FROM python:3.11-alpine3.19

# Set source directory
WORKDIR /app

# Copy source
COPY phase_cli ./phase_cli
COPY setup.py requirements.txt LICENSE README.md ./

# Install build dependencies and the CLI
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev && \
    pip install --no-cache-dir . && \
    apk del .build-deps

# CLI Entrypoint
ENTRYPOINT ["phase"]

# Run help by default
CMD ["--help"]