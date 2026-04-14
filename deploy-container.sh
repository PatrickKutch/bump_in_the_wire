#!/bin/bash

# Deploy bitw_xdp container to encoder and decoder hosts
# Usage: ./deploy-to-ifed.sh [remote_user]

set -e  # Exit on any error

# Configuration
REMOTE_HOSTS=("encoder" "decoder")
REMOTE_USER="${1:-root}"
CONTAINER_IMAGE="bitw_xdp:docker-only"
TEMP_FILE="bitw_xdp-docker-only.tar.gz"

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

# Function to cleanup remote temp files on all hosts
cleanup_remote() {
    for REMOTE_HOST in "${REMOTE_HOSTS[@]}"; do
        REMOTE_PATH="/tmp/${TEMP_FILE}"
        log_info "Cleaning up remote temp file on ${REMOTE_HOST}: ${REMOTE_PATH}"
        ssh "${REMOTE_USER}@${REMOTE_HOST}" "rm -f '${REMOTE_PATH}'" 2>/dev/null || true
    done
}

# Function to deploy to a single host
deploy_to_host() {
    local REMOTE_HOST="$1"
    local REMOTE_PATH="/tmp/${TEMP_FILE}"
    
    log_info "=== Deploying to ${REMOTE_HOST} ==="
    
    # Test SSH connectivity
    log_info "Testing SSH connectivity to ${REMOTE_USER}@${REMOTE_HOST}..."
    if ! ssh -o ConnectTimeout=10 "${REMOTE_USER}@${REMOTE_HOST}" "echo 'SSH connection successful'" 2>/dev/null; then
        log_error "Failed to connect to ${REMOTE_USER}@${REMOTE_HOST}"
        log_error "Please check:"
        log_error "  - Host is reachable"
        log_error "  - SSH keys are configured"
        log_error "  - Username is correct"
        return 1
    fi
    log_success "SSH connectivity confirmed for ${REMOTE_HOST}"

    # Transfer container to remote host
    log_info "Transferring container to ${REMOTE_HOST}..."
    if scp "${TEMP_FILE}" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}"; then
        log_success "Container transferred successfully to ${REMOTE_HOST}"
    else
        log_error "Failed to transfer container to ${REMOTE_HOST}"
        return 1
    fi

    # Load container on remote host using podman
    log_info "Loading container on ${REMOTE_HOST} using podman..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" << EOF
set -e

echo "Loading container image with podman..."
gunzip -c "${REMOTE_PATH}" | podman load

echo "Verifying container was loaded..."
echo "Checking for image: ${CONTAINER_IMAGE}"
if podman images --format "{{.Repository}}:{{.Tag}}" | grep -q "bitw_xdp:docker-only"; then
    echo "✅ Container loaded successfully on ${REMOTE_HOST}"
    podman images | grep bitw_xdp
else
    echo "❌ Container failed to load on ${REMOTE_HOST}"
    echo "Available images:"
    podman images --format "{{.Repository}}:{{.Tag}}"
    exit 1
fi

echo "Cleaning up remote temp file..."
rm -f "${REMOTE_PATH}"
EOF

    if [[ $? -eq 0 ]]; then
        log_success "Container deployment to ${REMOTE_HOST} completed successfully!"
        return 0
    else
        log_error "Container deployment to ${REMOTE_HOST} failed"
        return 1
    fi
}

# Trap to ensure cleanup on exit
trap 'cleanup_local; cleanup_remote' EXIT

log_info "Starting container deployment to encoder and decoder systems"
log_info "Remote user: ${REMOTE_USER}"
log_info "Target hosts: ${REMOTE_HOSTS[*]}"

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

# Step 3: Deploy to all hosts
FAILED_HOSTS=()
SUCCESSFUL_HOSTS=()

for REMOTE_HOST in "${REMOTE_HOSTS[@]}"; do
    if deploy_to_host "${REMOTE_HOST}"; then
        SUCCESSFUL_HOSTS+=("${REMOTE_HOST}")
    else
        FAILED_HOSTS+=("${REMOTE_HOST}")
    fi
    echo  # Add blank line between host deployments
done

# Step 4: Summary
log_info "=== Deployment Summary ==="
if [[ ${#SUCCESSFUL_HOSTS[@]} -gt 0 ]]; then
    log_success "Successfully deployed to: ${SUCCESSFUL_HOSTS[*]}"
fi

if [[ ${#FAILED_HOSTS[@]} -gt 0 ]]; then
    log_error "Failed to deploy to: ${FAILED_HOSTS[*]}"
    exit 1
fi

log_success "All deployments completed successfully!"
log_info ""
log_info "The container is now available on all target hosts as: ${CONTAINER_IMAGE}"
log_info ""
log_info "To run the container on encoder/decoder hosts:"
log_info "  ssh root@encoder  # or decoder"
log_info "  cd /root  # or wherever you want to run from"
log_info "  podman run --privileged --network=host --rm \\"
log_info "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
log_info "    ${CONTAINER_IMAGE} eth0 eth1 --sample.sampling=1000 --sample.ethertypes=0x800"
log_info ""
log_info "Example S-Flow usage:"
log_info "  # On encoder: Run bitw_sflow to sample and watermark packets"
log_info "  podman run --privileged --network=host --rm \\"
log_info "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
log_info "    ${CONTAINER_IMAGE} --mode sflow eth0 eth1 --sample.sampling=1000 --sample.ethertypes=0x800"
log_info ""
log_info "  # On decoder: Run bitw_filter to detect and remove watermarks"
log_info "  podman run --privileged --network=host --rm \\"
log_info "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
log_info "    ${CONTAINER_IMAGE} --mode filter eth0 eth1"