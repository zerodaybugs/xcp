#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mode="${1:-}"
key_dir=/tmp/bucket-key
payload_dir=/tmp/private-bucket-payload
result_dir=/tmp/private-bucket-result
public_dir="$GITHUB_WORKSPACE/bucket_public_metadata"

prepare() {
  rm -rf "$key_dir" "$public_dir"
  mkdir -p "$key_dir" "$public_dir"
  uname -a > "$public_dir/UNAME.txt"
  openssl version -a > "$public_dir/OPENSSL_VERSION.txt"
  python3 --version > "$public_dir/PYTHON_VERSION.txt"
  node --version > "$public_dir/NODE_VERSION.txt"
  openssl req \
    -x509 \
    -newkey rsa:4096 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=ephemeral-bucket-input-${GITHUB_RUN_ID}" \
    -keyout "$key_dir/private.pem" \
    -out "$key_dir/certificate.pem" \
    >/dev/null 2>&1
  chmod 600 "$key_dir/private.pem"
  openssl x509 \
    -in "$key_dir/certificate.pem" \
    -noout -fingerprint -sha256 -subject -dates \
    > "$public_dir/INPUT_CERTIFICATE_METADATA.txt"
  cp "$key_dir/certificate.pem" "$public_dir/input_certificate.pem"
}

run_private() {
  test -n "${GITHUB_HEAD_REF:-}"
  rm -rf "$payload_dir" "$result_dir"
  mkdir -p "$payload_dir" "$payload_dir/results" "$result_dir" "$result_dir/bundle/public_metadata"

  inbox_dir=".tooling/ephemeral-private-runner/inbox/bucket-move-${GITHUB_RUN_ID}"
  ready_path="${inbox_dir}/READY"
  remote_ref='refs/remotes/ephemeral-bucket-payload/head'
  found=false

  for attempt in $(seq 1 1440); do
    git fetch --quiet --no-tags --depth=1 \
      "https://github.com/${GITHUB_REPOSITORY}.git" \
      "+refs/heads/${GITHUB_HEAD_REF}:${remote_ref}" \
      >/dev/null 2>&1 || true
    if git show "${remote_ref}:${ready_path}" > "$key_dir/READY" 2>/dev/null; then
      mapfile -t parts < <(
        git ls-tree -r --name-only "$remote_ref" -- "$inbox_dir" \
          | grep -E '/part-[0-9]{4}$' \
          | sort
      )
      if test "${#parts[@]}" -gt 0; then
        : > "$key_dir/payload.cms.b64"
        for part in "${parts[@]}"; do
          git show "${remote_ref}:${part}" >> "$key_dir/payload.cms.b64"
        done
        base64 --decode "$key_dir/payload.cms.b64" > "$key_dir/payload.cms"
        expected="$(tr -d '[:space:]' < "$key_dir/READY")"
        actual="$(sha256sum "$key_dir/payload.cms" | awk '{print $1}')"
        if test -s "$key_dir/payload.cms" && test "$actual" = "$expected"; then
          printf '%s\n' "${#parts[@]}" > "$public_dir/ENCRYPTED_PAYLOAD_PART_COUNT.txt"
          found=true
          break
        fi
      fi
    fi
    sleep 5
  done
  test "$found" = true
  sha256sum "$key_dir/payload.cms" > "$public_dir/ENCRYPTED_PAYLOAD_SHA256.txt"

  openssl cms \
    -decrypt \
    -binary \
    -inform DER \
    -in "$key_dir/payload.cms" \
    -recip "$key_dir/certificate.pem" \
    -inkey "$key_dir/private.pem" \
    -out "$key_dir/payload.tar" \
    >/dev/null 2>&1

  python3 - "$key_dir/payload.tar" "$payload_dir" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
with tarfile.open(archive, 'r:*') as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit('empty payload')
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts:
            raise SystemExit('unsafe payload path')
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit('unsupported payload member')
    tf.extractall(target, members=members, filter='data')
PY

  test -f "$payload_dir/MANIFEST.sha256"
  test -f "$payload_dir/run.sh"
  test -f "$payload_dir/result_cert.pem"
  (
    cd "$payload_dir"
    sha256sum -c MANIFEST.sha256 > "$result_dir/PAYLOAD_INTEGRITY.log" 2>&1
  )
  chmod 700 "$payload_dir/run.sh"

  set +e
  (
    cd "$payload_dir"
    env \
      PRIVATE_RUNNER_RESULTS="$payload_dir/results" \
      PRIVATE_RUNNER_PUBLIC_METADATA="$public_dir" \
      bash ./run.sh
  ) > "$result_dir/PRIVATE_RUN.log" 2>&1
  private_status=$?
  set -e
  printf '%s\n' "$private_status" > "$result_dir/PRIVATE_RUN_STATUS.txt"

  cp -a "$result_dir/PRIVATE_RUN.log" "$result_dir/bundle/"
  cp -a "$result_dir/PRIVATE_RUN_STATUS.txt" "$result_dir/bundle/"
  cp -a "$result_dir/PAYLOAD_INTEGRITY.log" "$result_dir/bundle/"
  cp -a "$payload_dir/results/." "$result_dir/bundle/" 2>/dev/null || true
  cp -a "$public_dir/." "$result_dir/bundle/public_metadata/"
  (
    cd "$result_dir/bundle"
    find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
  )
  tar -cf "$result_dir/result.tar" -C "$result_dir/bundle" .
  openssl cms \
    -encrypt \
    -binary \
    -aes256 \
    -in "$result_dir/result.tar" \
    -outform DER \
    -out "$result_dir/encrypted-result.cms" \
    "$payload_dir/result_cert.pem" \
    >/dev/null 2>&1
  sha256sum "$result_dir/encrypted-result.cms" > "$result_dir/ENCRYPTED_RESULT_SHA256.txt"
  printf '%s\n' "$private_status" > "$result_dir/RESULT_STATUS.txt"

  rm -rf "$payload_dir" "$key_dir" "$result_dir/result.tar" "$result_dir/bundle"
  exit "$private_status"
}

case "$mode" in
  prepare) prepare ;;
  run) run_private ;;
  *) echo "usage: $0 prepare|run" >&2; exit 2 ;;
esac
