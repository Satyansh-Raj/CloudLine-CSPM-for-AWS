#!/usr/bin/env bash
# package_lambda.sh — Build the CloudLine Lambda deployment zip.
#
# Usage:
#   ./scripts/package_lambda.sh
#
# Outputs:
#   deployment.zip in the repository root.
#
# Prerequisites:
#   - docker or podman on PATH (used to build deps in Lambda-compatible env)
#   - Internet access (first run, to download OPA binary)
#
# Why Docker/Podman is required:
#   pydantic-core and other packages with compiled C/Rust extensions (.so
#   files) must be built inside the Lambda runtime image
#   (public.ecr.aws/lambda/python:3.11) to get binaries that match
#   Lambda's Python 3.11 + Amazon Linux 2023 ABI.  Building on the host
#   system produces the wrong cpython version tag and/or wrong glibc.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPA_VERSION="0.68.0"
OPA_BINARY_URL="https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static"

# Resolve repository root regardless of where the script is called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_DIR="${REPO_ROOT}/build"
CACHE_DIR="${REPO_ROOT}/.lambda-cache"
OPA_CACHED="${CACHE_DIR}/opa_linux_amd64_static_${OPA_VERSION}"
ZIP_OUTPUT="${REPO_ROOT}/deployment.zip"

# ---------------------------------------------------------------------------
# Validate required source directories
# ---------------------------------------------------------------------------
for required in \
    "${REPO_ROOT}/lambda/handler.py" \
    "${REPO_ROOT}/lambda/requirements.txt" \
    "${REPO_ROOT}/backend/app" \
    "${REPO_ROOT}/policies"; do
    if [[ ! -e "${required}" ]]; then
        echo "ERROR: Required path not found: ${required}" >&2
        exit 1
    fi
done

echo "==> Repository root : ${REPO_ROOT}"
echo "==> Build directory : ${BUILD_DIR}"
echo "==> Output zip      : ${ZIP_OUTPUT}"

# ---------------------------------------------------------------------------
# Download OPA binary (cached)
# ---------------------------------------------------------------------------
mkdir -p "${CACHE_DIR}"

if [[ ! -f "${OPA_CACHED}" ]]; then
    echo "==> Downloading OPA v${OPA_VERSION} ..."
    curl -fsSL -o "${OPA_CACHED}" "${OPA_BINARY_URL}"
    chmod +x "${OPA_CACHED}"
    echo "    Cached at ${OPA_CACHED}"
else
    echo "==> OPA binary already cached: ${OPA_CACHED}"
fi

# ---------------------------------------------------------------------------
# Clean and prepare build directory
# ---------------------------------------------------------------------------
echo "==> Preparing build directory ..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/bin"

# ---------------------------------------------------------------------------
# Copy Lambda entrypoint
# ---------------------------------------------------------------------------
echo "==> Copying lambda/handler.py ..."
cp "${REPO_ROOT}/lambda/handler.py" "${BUILD_DIR}/handler.py"

# ---------------------------------------------------------------------------
# Copy application package
# ---------------------------------------------------------------------------
echo "==> Copying backend/app/ ..."
cp -r "${REPO_ROOT}/backend/app" "${BUILD_DIR}/app"

# Remove __pycache__ directories to keep the zip clean
find "${BUILD_DIR}/app" -type d -name "__pycache__" \
    -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Copy Rego policies
# ---------------------------------------------------------------------------
echo "==> Copying policies/ ..."
cp -r "${REPO_ROOT}/policies" "${BUILD_DIR}/policies"

# ---------------------------------------------------------------------------
# Copy OPA binary
# ---------------------------------------------------------------------------
echo "==> Installing OPA binary into build/bin/ ..."
cp "${OPA_CACHED}" "${BUILD_DIR}/bin/opa"
chmod +x "${BUILD_DIR}/bin/opa"

# ---------------------------------------------------------------------------
# Install Python dependencies inside the Lambda runtime image
# ---------------------------------------------------------------------------
echo "==> Installing Python dependencies (Lambda-compatible build) ..."

# Detect docker or podman
CONTAINER_CLI=""
if command -v docker &>/dev/null; then
    CONTAINER_CLI="docker"
elif command -v podman &>/dev/null; then
    CONTAINER_CLI="podman"
else
    echo "ERROR: docker or podman is required to build Lambda-compatible" \
         "binaries." >&2
    exit 1
fi
echo "    Using: ${CONTAINER_CLI}"

# Copy requirements.txt into build dir so the container can see it
cp "${REPO_ROOT}/lambda/requirements.txt" "${BUILD_DIR}/requirements.txt"

# Run pip inside the official Lambda Python 3.11 image.
# --entrypoint overrides the Lambda image's default entrypoint so we can
# run pip directly.  The build dir is mounted at /var/task.
${CONTAINER_CLI} run --rm \
    --entrypoint pip \
    -v "${BUILD_DIR}:/var/task" \
    "public.ecr.aws/lambda/python:3.11" \
    install \
        --quiet \
        --requirement /var/task/requirements.txt \
        --target /var/task \
        --upgrade

# Remove the copied requirements file (not needed in the zip)
rm -f "${BUILD_DIR}/requirements.txt"

# Clean up pip metadata to reduce zip size
find "${BUILD_DIR}" -type d -name "*.dist-info" \
    -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type d -name "*.egg-info" \
    -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Create deployment zip
# ---------------------------------------------------------------------------
echo "==> Creating deployment.zip ..."
rm -f "${ZIP_OUTPUT}"

cd "${BUILD_DIR}"
zip -r "${ZIP_OUTPUT}" . -x "*.pyc" -x "*/__pycache__/*" -q
cd "${REPO_ROOT}"

ZIP_SIZE=$(du -sh "${ZIP_OUTPUT}" | cut -f1)
echo ""
echo "Lambda package ready: deployment.zip (${ZIP_SIZE})"
echo "Path: ${ZIP_OUTPUT}"
