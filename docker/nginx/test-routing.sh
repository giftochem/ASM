#!/bin/sh
# Real-nginx routing regression for docker/nginx/nginx.conf (Stage D.1).
#
# Runs the production config, unmodified, in the production image
# against a stub API (answers everything with JSON naming the request it
# got) and a marker SPA page, then checks where every kind of request
# lands: SPA page loads -- including the pages that share paths with the
# API -- get the SPA; API calls, writes and API-only paths reach the API
# with their method and URI intact; headers are right on both sides.
#
# Needs Docker and the placeholder TLS certificates docs/deployment.md
# has you generate (docker/nginx/certs/fullchain.pem, privkey.pem). It
# never touches a running stack: everything runs on a throwaway network
# and is removed on exit.
#
#   sh docker/nginx/test-routing.sh
set -eu

cd "$(dirname "$0")/../.."
IMAGE=nginx:1.27-alpine
CONF=${NGINX_CONF:-docker/nginx/nginx.conf} # override to check another config
NET=asm-routing-test-$$
API=asm-routing-api-$$
WEB=asm-routing-web-$$
TMP=$(mktemp -d)
# Git Bash: never rewrite container-side paths in docker arguments (curl and
# the rest still need its host-path conversion).
dk() { MSYS_NO_PATHCONV=1 docker "$@"; }

# docker cp needs native host paths on Windows (Git Bash); a no-op elsewhere.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

cleanup() {
    dk rm -f "$WEB" "$API" >/dev/null 2>&1 || true
    dk network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

for cert in fullchain.pem privkey.pem; do
    if [ ! -f "docker/nginx/certs/$cert" ]; then
        echo "missing docker/nginx/certs/$cert -- generate the placeholder certificates first (docs/deployment.md)" >&2
        exit 2
    fi
done

cat >"$TMP/api.conf" <<'EOF'
server {
    listen 8000;
    default_type application/json;
    location / { return 200 '{"stub_api":true,"method":"$request_method","uri":"$request_uri"}\n'; }
}
EOF
printf '<!doctype html><title>asm-spa-marker</title>\n' >"$TMP/index.html"
mkdir -p "$TMP/static"
printf '/* asm-static-marker */\n' >"$TMP/static/index-test.js"

dk network create "$NET" >/dev/null
dk create --name "$API" --network "$NET" --network-alias app "$IMAGE" >/dev/null
dk cp "$(native "$TMP/api.conf")" "$API:/etc/nginx/conf.d/default.conf"
dk start "$API" >/dev/null

dk create --name "$WEB" --network "$NET" -p 127.0.0.1::443 "$IMAGE" >/dev/null
dk cp "$(native "$PWD/$CONF")" "$WEB:/etc/nginx/conf.d/default.conf"
dk cp "$(native "$PWD/docker/nginx/certs")" "$WEB:/etc/nginx/certs"
dk cp "$(native "$TMP/index.html")" "$WEB:/usr/share/nginx/html/index.html"
dk cp "$(native "$TMP/static")" "$WEB:/usr/share/nginx/html/static"
dk start "$WEB" >/dev/null
dk exec "$WEB" nginx -t >/dev/null 2>&1 || { echo "nginx -t failed:" >&2; dk exec "$WEB" nginx -t >&2; exit 1; }

PORT=$(dk port "$WEB" 443/tcp | head -n 1 | sed 's/.*://')
BASE="https://127.0.0.1:$PORT"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -sk -o /dev/null "$BASE/" && break
    sleep 1
done

HTML='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
UUID=11111111-2222-3333-4444-555555555555
FAILED=0

# check <spa|api> <METHOD> <path> <Accept> [shared]
#   spa: the marker page, as HTML; api: the stub's JSON echoing this method and URI.
#   shared: the path is also an SPA page -- expect Vary: Accept (and, for
#   the page itself, Cache-Control: no-cache).
check() {
    want=$1 method=$2 path=$3 accept=$4 shared=${5:-}
    if [ "$method" = HEAD ]; then
        curl -sk -I -H "Accept: $accept" "$BASE$path" >"$TMP/headers"
        : >"$TMP/body"
    else
        curl -sk -X "$method" -H "Accept: $accept" -D "$TMP/headers" -o "$TMP/body" "$BASE$path"
    fi
    problems=""
    if [ "$want" = spa ]; then
        grep -qi '^content-type: text/html' "$TMP/headers" || problems="$problems not-html"
        [ "$method" = HEAD ] || grep -q 'asm-spa-marker' "$TMP/body" || problems="$problems not-the-spa"
        if [ -n "$shared" ]; then
            grep -qi '^cache-control: no-cache' "$TMP/headers" || problems="$problems no-cache-control"
        fi
    else
        grep -q '"stub_api":true' "$TMP/body" || problems="$problems not-the-api"
        grep -qF "\"method\":\"$method\"" "$TMP/body" || problems="$problems method-changed"
        grep -qF "\"uri\":\"$path\"" "$TMP/body" || problems="$problems uri-changed"
        if grep -qi '^cache-control:' "$TMP/headers"; then problems="$problems unexpected-cache-control"; fi
    fi
    if [ -n "$shared" ]; then
        grep -qi '^vary: accept' "$TMP/headers" || problems="$problems no-vary"
    elif grep -qi '^vary: accept' "$TMP/headers"; then
        problems="$problems unexpected-vary"
    fi
    grep -qi '^x-frame-options: deny' "$TMP/headers" || problems="$problems no-security-headers"
    if [ -n "$problems" ]; then
        FAILED=$((FAILED + 1))
        printf 'FAIL %-7s %-60s [%s] ->%s\n' "$method" "$path" "$accept" "$problems"
    else
        printf 'ok   %-7s %-60s [%.24s] -> %s\n' "$method" "$path" "$accept" "$want"
    fi
}

# SPA page loads, including the pages that share paths with the API.
check spa GET / "$HTML"
check spa GET /exposure-paths "$HTML"
check spa GET /changes "$HTML"
check spa GET /settings/users "$HTML"
check spa GET /login "$HTML"
check spa GET /no-such-page "$HTML"
check spa GET /assets "$HTML" shared
check spa GET /assets/ "$HTML" shared
check spa GET "/assets?search=example" "$HTML" shared
check spa GET "/assets/$UUID" "$HTML" shared
check spa GET /alerts "$HTML" shared
check spa GET /scans "$HTML" shared
check spa GET "/scans?asset_id=$UUID" "$HTML" shared
check spa GET "/scans/$UUID" "$HTML" shared
check spa GET /findings "$HTML" shared
check spa GET /reports "$HTML" shared
check spa HEAD "/assets/$UUID" "$HTML" shared
check spa GET "/assets/$UUID" "TEXT/HTML" shared

# API calls on the same paths (fetch sends */*), and writes even with an HTML Accept.
check api GET /assets "*/*" shared
check api GET /assets "application/json" shared
check api GET "/assets/$UUID" "*/*" shared
check api GET "/scans?asset_id=$UUID" "*/*" shared
check api GET /alerts "*/*" shared
check api GET /reports "*/*" shared
check api POST /assets "$HTML" shared
check api PATCH "/assets/$UUID" "$HTML" shared
check api DELETE "/scans/$UUID" "$HTML" shared
check api OPTIONS /assets "$HTML" shared

# API-only paths stay API even for a browser page load.
check api GET /assets/activity "$HTML"
check api GET "/assets/$UUID/graph" "$HTML"
check api GET "/reports/$UUID/download" "$HTML"
check api GET /assets/not-a-uuid "$HTML"
check api GET /assets/exposure-paths "$HTML"
check api GET /audit-logs "$HTML"
check api GET /users/me "$HTML"
check api POST /auth/login "$HTML"
check api GET /discovery/providers "$HTML"
check api GET /health "$HTML"
check api GET /docs "$HTML"
check api GET /openapi.json "$HTML"

# The production build's bundles (vite.config.ts build.assetsDir = "static")
# are static files -- never the API. Anything under /assets/ goes to the API,
# which is why the build must not put its bundles there.
curl -sk -D "$TMP/headers" -o "$TMP/body" "$BASE/static/index-test.js"
if grep -qi '^content-type: application/javascript' "$TMP/headers" && grep -q 'asm-static-marker' "$TMP/body"; then
    printf 'ok   %-7s %-60s -> static file\n' GET /static/index-test.js
else
    FAILED=$((FAILED + 1))
    printf 'FAIL %-7s %-60s -> not served as a static file\n' GET /static/index-test.js
fi
check api GET /assets/index-test.js "*/*"

if [ "$FAILED" -ne 0 ]; then
    echo "$FAILED routing check(s) failed" >&2
    exit 1
fi
echo "all routing checks passed"
