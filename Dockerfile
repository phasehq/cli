FROM alpine:latest

COPY ./dist/phase /usr/local/bin/phase

RUN chmod +x /usr/local/bin/phase