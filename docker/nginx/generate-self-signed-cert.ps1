# Step 7B: generates a self-signed TLS cert/key for docker-compose.prod.yml's
# nginx, using a throwaway Docker container -- openssl isn't installed on
# this host, so this borrows a container that has it rather than requiring
# a host install. Output lands in docker/nginx/certs/, which is gitignored:
# even a self-signed private key must never be committed.
#
# This is a placeholder for local/staging use only (browsers will show a
# trust warning). Replace with a CA-issued cert (Let's Encrypt/ACME or
# otherwise) before this is exposed to real users -- see docs/deployment.md.

$ErrorActionPreference = "Stop"

$certsDir = Join-Path $PSScriptRoot "certs"
if (-not (Test-Path $certsDir)) {
    New-Item -ItemType Directory -Path $certsDir | Out-Null
}

docker run --rm -v "${certsDir}:/certs" alpine/openssl req -x509 -nodes `
    -newkey rsa:2048 `
    -keyout /certs/privkey.pem `
    -out /certs/fullchain.pem `
    -days 365 `
    -subj "/CN=localhost"

Write-Output "Wrote $certsDir\fullchain.pem and $certsDir\privkey.pem (self-signed, 365 days)."
