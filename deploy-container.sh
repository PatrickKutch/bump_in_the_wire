#!/bin/bash

# Deploy bitw_xdp container to remote host
# Usage: ./deploy-container.sh [remote_host] [remote_user]

set -e  # Exit on any error

# Configuration
REMOTE_HOST="${1:-npg-svr-33}"
REMOTE_USER="${2:-root}"
CONTAINER_IMAGE="bitw_xdp:docker-only"
TEMP_FILE="bitw_xdp-docker-only.tar.gz"
REMOTE_PATH="/tmp/${TEMP_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed or not in PATH"
        exit 1
    fi
}

# Function to cleanup local temp files
cleanup_local() {
    if [[ -f "${TEMP_FILE}" ]]; then
        log_info "Cleaning up local temp file: ${TEMP_FILE}"
        rm -f "${TEMP_FILE}"
    fi
}

# Function to cleanup remote temp files
cleanup_remote() {
    log_info "Cleaning up remote temp file: ${REMOTE_PATH}"
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "rm -f '${REMOTE_PATH}'" 2>/dev/null || true
}

# Trap to ensure cleanup on exit
trap 'cleanup_local; cleanup_remote' EXIT

log_info "Starting container deployment to ${REMOTE_USER}@${REMOTE_HOST}"

# Check required commands
check_command docker
check_command ssh
check_command scp

# Step 1: Build container if it doesn't exist
log_info "Checking if container image exists..."
if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${CONTAINER_IMAGE}$"; then
    log_warn "Container image not found, building..."
    if [[ -x "./build-docker-only.sh" ]]; then
        ./build-docker-only.sh
    else
        log_info "Running manual docker build..."
        docker build -t "${CONTAINER_IMAGE}" .
    fi
else
    log_success "Container image found: ${CONTAINER_IMAGE}"
fi

# Step 2: Save container to compressed tar file
log_info "Exporting container to compressed archive..."
docker save "${CONTAINER_IMAGE}" | gzip > "${TEMP_FILE}"
ARCHIVE_SIZE=$(du -h "${TEMP_FILE}" | cut -f1)
log_success "Container exported to ${TEMP_FILE} (${ARCHIVE_SIZE})"

# Step 3: Test SSH connectivity
log_info "Testing SSH connectivity to ${REMOTE_USER}@${REMOTE_HOST}..."
if ! ssh -o ConnectTimeout=10 "${REMOTE_USER}@${REMOTE_HOST}" "echo 'SSH connection successful'" 2>/dev/null; then
    log_error "Failed to connect to ${REMOTE_USER}@${REMOTE_HOST}"
    log_error "Please check:"
    log_error "  - Host is reachable"
    log_error "  - SSH keys are configured"
    log_error "  - Username is correct"
    exit 1
fi
log_success "SSH connectivity confirmed"

# Step 4: Transfer container to remote host
log_info "Transferring container to remote host..."
if scp "${TEMP_FILE}" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}"; then
    log_success "Container transferred successfully"
else
    log_error "Failed to transfer container"
    exit 1
fi

# Step 5: Load container on remote host
log_info "Loading container on remote host..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" << EOF
set -e

echo "Loading container image..."
gunzip -c "${REMOTE_PATH}" | docker load

echo "Verifying container was loaded..."
if docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${CONTAINER_IMAGE}$"; then
    echo "✅ Container loaded successfully"
    docker images | grep bitw_xdp
else
    echo "❌ Container failed to load"
    exit 1
fi

echo "Cleaning up remote temp file..."
rm -f "${REMOTE_PATH}"
EOF

if [[ $? -eq 0 ]]; then
    log_success "Container deployment completed successfully!"
    log_info ""
    log_info "The container is now available on ${REMOTE_HOST} as: ${CONTAINER_IMAGE}"
    log_info ""
    log_info "To run the container on the remote host:"
    log_info "  ssh ${REMOTE_USER}@${REMOTE_HOST}"
    log_info "  sudo docker run --privileged --network=host --rm \\"
    log_info "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
    log_info "    ${CONTAINER_IMAGE} PF0 PF1 --sample.sampling=1000 --sample.ethertypes=0x800"
else
    log_error "Container deployment failed on remote host"
    exit 1
fi