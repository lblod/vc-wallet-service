# VC Issuer service

> [!WARNING]
> This service is currently under development and cannot be used in a production context yet

## Generating certificates

This service needs a public x509 certificate to work properly. You can generate this (and its corresponding private key) using `openssl req -new -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out public_cert.pem -keyout private_cert.pem `
