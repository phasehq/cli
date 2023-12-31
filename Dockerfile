FROM alpine:latest

# Copy the phase executable
COPY ./dist/phase /usr/local/bin/phase

# Copy the _internal directory
COPY ./dist/_internal /usr/local/bin/_internal

# Give execute permission to the phase binary
RUN chmod +x /usr/local/bin/phase
