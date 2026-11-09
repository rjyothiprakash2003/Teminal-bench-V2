#!/bin/bash
set -uo pipefail

# Check if we're in a valid working directory
if [ "$PWD" = "/" ]; then
    echo "Error: No working directory set. Please set a WORKDIR in your Dockerfile before running this script."
    mkdir -p /logs/verifier
    echo 0 > /logs/verifier/reward.txt
    exit 0
fi

mkdir -p /logs/verifier /tmp/pytest_cache /home/model/tmp /home/model/go/cache
chmod u+rwx /logs/verifier /tmp/pytest_cache 2>/dev/null || true

# Stage tests onto a container-local root-only tree. Bind-mounted /tests can remain
# readable across UID maps on some hosts; /opt/verifier is image-local and stays locked.
HIDDEN_TESTS=/opt/verifier/hidden-tests
if [ "$(id -u)" -eq 0 ]; then
  rm -rf "$HIDDEN_TESTS"
  mkdir -p "$HIDDEN_TESTS"
  if [ -e /tests ]; then
    cp -a /tests/. "$HIDDEN_TESTS"/
    chown root:root /tests 2>/dev/null || true
    chmod 700 /tests 2>/dev/null || true
    find /tests -mindepth 1 -exec chown root:root {} + 2>/dev/null || true
    find /tests -type d -exec chmod 700 {} + 2>/dev/null || true
    find /tests -type f -exec chmod 600 {} + 2>/dev/null || true
  fi
  chown root:root "$HIDDEN_TESTS"
  chmod 700 "$HIDDEN_TESTS"
  find "$HIDDEN_TESTS" -type d -exec chmod 700 {} +
  find "$HIDDEN_TESTS" -type f -exec chmod 600 {} +
  if [ -d /solution ]; then
    chown root:root /solution 2>/dev/null || true
    chmod 700 /solution 2>/dev/null || true
  fi
  # Agents often run make verify as root and leave root-owned build/cache artifacts.
  # Clear and re-own them before the graded model-user make/antlock invocations.
  rm -rf /app/build /home/model/go/cache /home/model/tmp
  mkdir -p /app/build /home/model/go/cache /home/model/tmp
  chown -R model:model /app /home/model 2>/dev/null || true
  chmod 755 /app /home/model /home/model/go /home/model/tmp /home/model/go/cache /app/build 2>/dev/null || true
else
  HIDDEN_TESTS=/tests
fi

# Remove any stale/pre-planted CTRF report so its post-run presence proves that a real
# pytest session executed (a swapped PATH python that just exits 0 cannot produce it).
rm -f /logs/verifier/ctrf.json

# Use the root-owned immutable verifier interpreter (not writable PATH python). Isolated
# mode prevents /app from shadowing installed pytest. CTRF gates keep reward honest.
# test_outputs.py drops make verify and antlock to model via runuser.
/opt/verifier/bin/python3 -I -m pytest -o cache_dir=/tmp/pytest_cache \
  --ctrf /logs/verifier/ctrf.json "$HIDDEN_TESTS/test_outputs.py" -rA \
  && [ -s /logs/verifier/ctrf.json ] \
  && grep -q '"failed":[[:space:]]*0' /logs/verifier/ctrf.json \
  && grep -Eq '"passed":[[:space:]]*[1-9][0-9]*' /logs/verifier/ctrf.json
rc=$?
if [ "$rc" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
