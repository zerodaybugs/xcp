#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mode="${1:-}"

to_posix_path() {
  local value="$1"
  if command -v cygpath >/dev/null 2>&1 && [[ "$value" =~ ^[A-Za-z]:[\\/] ]]; then
    cygpath -u "$value"
  else
    printf '%s\n' "$value"
  fi
}

runner_temp="$(to_posix_path "${RUNNER_TEMP:-/tmp}")"
workspace="$(to_posix_path "${GITHUB_WORKSPACE:-$PWD}")"
key_dir="$runner_temp/private-validation-key"
payload_dir="$runner_temp/private-validation-payload"
result_dir="$runner_temp/private-validation-result"
public_dir="$workspace/private_validation_public_metadata"

find_openssl() {
  if command -v openssl >/dev/null 2>&1; then
    command -v openssl
    return
  fi
  for candidate in \
    '/c/Program Files/Git/usr/bin/openssl.exe' \
    '/c/Program Files/OpenSSL/bin/openssl.exe' \
    '/c/Program Files/OpenSSL-Win64/bin/openssl.exe'; do
    if test -x "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

OPENSSL_BIN="$(find_openssl)"

prepare() {
  rm -rf "$key_dir" "$public_dir"
  mkdir -p "$key_dir" "$public_dir"

  {
    printf 'runner_temp=%s\n' "$runner_temp"
    printf 'workspace=%s\n' "$workspace"
    printf 'openssl=%s\n' "$OPENSSL_BIN"
  } > "$public_dir/PATH_DIAGNOSTICS.txt"

  uname -a > "$public_dir/UNAME.txt" 2>&1 || true
  "$OPENSSL_BIN" version -a > "$public_dir/OPENSSL_VERSION.txt" 2>&1 || true
  (python --version || python3 --version || py -3 --version) > "$public_dir/PYTHON_VERSION.txt" 2>&1 || true
  rustc --version > "$public_dir/RUST_VERSION.txt" 2>&1 || true
  cmake --version > "$public_dir/CMAKE_VERSION.txt" 2>&1 || true

  if ! MSYS2_ARG_CONV_EXCL='/CN=' "$OPENSSL_BIN" req \
    -x509 \
    -newkey rsa:4096 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=ephemeral-windows-input-${GITHUB_RUN_ID}" \
    -keyout "$key_dir/private.pem" \
    -out "$key_dir/certificate.pem" \
    > "$public_dir/OPENSSL_REQ.stdout.txt" \
    2> "$public_dir/OPENSSL_REQ.stderr.txt"; then
      cat "$public_dir/OPENSSL_REQ.stderr.txt" >&2 || true
      exit 1
  fi

  test -s "$key_dir/private.pem"
  test -s "$key_dir/certificate.pem"
  chmod 600 "$key_dir/private.pem"
  "$OPENSSL_BIN" x509 \
    -in "$key_dir/certificate.pem" \
    -noout -fingerprint -sha256 -subject -dates \
    > "$public_dir/INPUT_CERTIFICATE_METADATA.txt"
  cp "$key_dir/certificate.pem" "$public_dir/input_certificate.pem"
}

safe_extract_tar() {
  local archive="$1"
  local target="$2"
  python - "$archive" "$target" <<'PY'
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
            raise SystemExit(f'unsafe payload path: {member.name!r}')
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f'unsupported payload member: {member.name!r}')
    try:
        tf.extractall(target, members=members, filter='data')
    except TypeError:
        tf.extractall(target, members=members)
PY
}

run_private() {
  test -n "${GITHUB_HEAD_REF:-}"
  rm -rf "$payload_dir" "$result_dir"
  mkdir -p "$payload_dir" "$payload_dir/results" "$result_dir" "$result_dir/bundle/public_metadata"

  inbox_dir=".tooling/ephemeral-private-runner/inbox/windows-${GITHUB_RUN_ID}"
  ready_path="${inbox_dir}/READY"
  remote_ref='refs/remotes/ephemeral-windows-payload/head'
  found=false

  for attempt in $(seq 1 2160); do
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

  "$OPENSSL_BIN" cms \
    -decrypt \
    -binary \
    -inform DER \
    -in "$key_dir/payload.cms" \
    -recip "$key_dir/certificate.pem" \
    -inkey "$key_dir/private.pem" \
    -out "$key_dir/payload.tar" \
    >/dev/null 2>&1

  safe_extract_tar "$key_dir/payload.tar" "$payload_dir"

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
  "$OPENSSL_BIN" cms \
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
