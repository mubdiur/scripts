#!/bin/bash

################################################################################
# VPS Log Rotation and Storage Cleanup Script
# Version: 1.0
# Description: Production-safe script to manage logs and free up disk space
# Safety: Multiple checks before deletion, dry-run mode available
################################################################################

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Configuration
readonly LOG_SIZE_LIMIT_MB=10
readonly LOG_SIZE_LIMIT_BYTES=$((LOG_SIZE_LIMIT_MB * 1024 * 1024))
readonly SCRIPT_LOG="/var/log/vps-cleanup.log"
readonly DRY_RUN="${DRY_RUN:-false}"  # Set DRY_RUN=true to test without deleting

# Docker Safety Configuration
# DOCKER_VOLUME_PROTECTION: Set to "true" to NEVER remove any volumes (even truly unused ones)
readonly DOCKER_VOLUME_PROTECTION="${DOCKER_VOLUME_PROTECTION:-false}"
# DOCKER_REMOVE_OLD_CONTAINERS: Set to "true" to remove exited containers older than 30 days
readonly DOCKER_REMOVE_OLD_CONTAINERS="${DOCKER_REMOVE_OLD_CONTAINERS:-false}"
# DOCKER_PRESERVE_LABELS: Volumes with these labels will NEVER be removed (comma-separated)
readonly DOCKER_PRESERVE_LABELS="${DOCKER_PRESERVE_LABELS:-keep,backup,production,prod,database,db}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

################################################################################
# Helper Functions
################################################################################

log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} - $*" | tee -a "$SCRIPT_LOG"
}

log_success() {
    echo -e "${GREEN}✓${NC} $*" | tee -a "$SCRIPT_LOG"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $*" | tee -a "$SCRIPT_LOG"
}

log_error() {
    echo -e "${RED}✗${NC} $*" | tee -a "$SCRIPT_LOG"
}

bytes_to_human() {
    local bytes=$1
    if [ "$bytes" -lt 1024 ]; then
        echo "${bytes}B"
    elif [ "$bytes" -lt $((1024 * 1024)) ]; then
        echo "$((bytes / 1024))KB"
    elif [ "$bytes" -lt $((1024 * 1024 * 1024)) ]; then
        echo "$((bytes / 1024 / 1024))MB"
    else
        echo "$((bytes / 1024 / 1024 / 1024))GB"
    fi
}

safe_delete() {
    local file="$1"
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "[DRY RUN] Would delete: $file"
        return 0
    fi
    
    if [ -f "$file" ] || [ -d "$file" ]; then
        rm -rf "$file" && log_success "Deleted: $file" || log_error "Failed to delete: $file"
    fi
}

safe_truncate() {
    local file="$1"
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "[DRY RUN] Would truncate: $file"
        return 0
    fi
    
    if [ -f "$file" ]; then
        truncate -s 0 "$file" && log_success "Truncated: $file" || log_error "Failed to truncate: $file"
    fi
}

get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}'
}

################################################################################
# Main Cleanup Functions
################################################################################

rotate_and_trim_logs() {
    local log_file="$1"
    local keep_size="$2"
    
    if [ ! -f "$log_file" ]; then
        return 0
    fi
    
    local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
    
    if [ "$file_size" -gt "$keep_size" ]; then
        local human_size=$(bytes_to_human "$file_size")
        log "Processing $log_file ($human_size)"
        
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would keep last ${LOG_SIZE_LIMIT_MB}MB of $log_file"
        else
            # Keep only the last N MB
            local temp_file="${log_file}.tmp"
            tail -c "$keep_size" "$log_file" > "$temp_file" && mv "$temp_file" "$log_file"
            log_success "Trimmed $log_file to ${LOG_SIZE_LIMIT_MB}MB (was $human_size)"
        fi
    fi
}

cleanup_pm2_logs() {
    log "=== Cleaning PM2 Logs ==="
    
    # Find PM2 home directory
    local pm2_home="${PM2_HOME:-$HOME/.pm2}"
    
    if [ ! -d "$pm2_home" ]; then
        log_warning "PM2 directory not found at $pm2_home"
        return 0
    fi
    
    # Rotate PM2 logs using PM2's built-in command if available
    if command -v pm2 &> /dev/null; then
        log "Flushing PM2 logs..."
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would run: pm2 flush"
        else
            pm2 flush 2>/dev/null || log_warning "PM2 flush failed"
        fi
    fi
    
    # Trim individual PM2 log files
    find "$pm2_home/logs" -type f -name "*.log" 2>/dev/null | while read -r logfile; do
        rotate_and_trim_logs "$logfile" "$LOG_SIZE_LIMIT_BYTES"
    done
    
    # Clean old PM2 logs (older than 7 days)
    find "$pm2_home/logs" -type f -name "*.log.*" -mtime +7 2>/dev/null | while read -r oldlog; do
        safe_delete "$oldlog"
    done
}

cleanup_docker_logs() {
    log "=== Cleaning Docker Logs ==="
    
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not found, skipping Docker cleanup"
        return 0
    fi
    
    # Truncate logs for ALL containers (running AND stopped)
    # This ensures we clean logs even for crashed/stopped containers
    docker ps -a -q 2>/dev/null | while read -r container_id; do
        local container_name=$(docker inspect --format='{{.Name}}' "$container_id" 2>/dev/null | sed 's/^\///' || echo "unknown")
        local container_state=$(docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null || echo "unknown")
        local log_file=$(docker inspect --format='{{.LogPath}}' "$container_id" 2>/dev/null || echo "")
        
        if [ -n "$log_file" ] && [ -f "$log_file" ]; then
            log "Processing logs for container: $container_name (state: $container_state)"
            rotate_and_trim_logs "$log_file" "$LOG_SIZE_LIMIT_BYTES"
        fi
    done
    
    log "Cleaning Docker system resources..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "[DRY RUN] Would prune Docker resources"
        docker system df 2>/dev/null || true
        
        # Show what would be removed
        log_warning "[DRY RUN] Dangling images that would be removed:"
        docker images -f "dangling=true" -q 2>/dev/null | wc -l || echo "0"
        
        log_warning "[DRY RUN] Volumes that would be checked (only truly unused ones removed):"
        docker volume ls -qf dangling=true 2>/dev/null | wc -l || echo "0"
        
        log_warning "[DRY RUN] Networks that would be removed:"
        docker network ls -q -f "dangling=true" 2>/dev/null | wc -l || echo "0"
    else
        # Remove dangling images (not used by ANY container, even stopped ones)
        docker image prune -f 2>/dev/null && log_success "Pruned dangling images" || log_warning "Image prune failed"
        
        # CRITICAL: Only remove volumes that are NOT attached to ANY container
        # Docker's volume prune is safe - it only removes volumes with no container references
        # This includes stopped, crashed, or exited containers
        
        if [ "$DOCKER_VOLUME_PROTECTION" = "true" ]; then
            log_warning "Volume protection enabled - skipping volume cleanup"
            log "To enable volume cleanup, run: DOCKER_VOLUME_PROTECTION=false vps-cleanup"
        else
            log "Checking for truly unused volumes (not attached to any container)..."
            local volumes_before=$(docker volume ls -q 2>/dev/null | wc -l)
            
            # Build filter for protected labels
            local label_filters=""
            IFS=',' read -ra LABELS <<< "$DOCKER_PRESERVE_LABELS"
            for label in "${LABELS[@]}"; do
                label_filters="$label_filters --filter label!=$label"
            done
            
            # The volume prune ensures EXTRA safety - only removes volumes with no container refs at all
            eval "docker volume prune -f $label_filters" 2>/dev/null && log_success "Pruned truly unused volumes" || log_warning "Volume prune failed"
            
            local volumes_after=$(docker volume ls -q 2>/dev/null | wc -l)
            local volumes_removed=$((volumes_before - volumes_after))
            
            if [ "$volumes_removed" -gt 0 ]; then
                log_success "Removed $volumes_removed truly unused volumes"
                log "Protected labels: $DOCKER_PRESERVE_LABELS"
            else
                log "No unused volumes to remove (all volumes are attached to containers or protected)"
            fi
        fi
        
        # Remove unused networks (safe - preserves networks used by any container)
        docker network prune -f 2>/dev/null && log_success "Pruned unused networks" || log_warning "Network prune failed"
        
        # Remove build cache older than 7 days (safe for faster rebuilds)
        docker builder prune -f --filter "until=168h" 2>/dev/null && log_success "Pruned old build cache (>7 days)" || log_warning "Builder prune failed"
        
        # Optional: Remove exited containers that are very old (30+ days)
        if [ "$DOCKER_REMOVE_OLD_CONTAINERS" = "true" ]; then
            log "Removing exited containers older than 30 days..."
            local containers_before=$(docker ps -a -q -f "status=exited" 2>/dev/null | wc -l)
            docker container prune -f --filter "until=720h" 2>/dev/null && log_success "Pruned old exited containers (>30 days)" || log_warning "Container prune failed"
            local containers_after=$(docker ps -a -q -f "status=exited" 2>/dev/null | wc -l)
            local containers_removed=$((containers_before - containers_after))
            if [ "$containers_removed" -gt 0 ]; then
                log_success "Removed $containers_removed old exited containers"
            fi
        else
            log "Exited container cleanup disabled (set DOCKER_REMOVE_OLD_CONTAINERS=true to enable)"
        fi
    fi
    
    # Show current Docker disk usage
    log "Current Docker disk usage:"
    docker system df 2>/dev/null || true
}

cleanup_dokploy_logs() {
    log "=== Cleaning Dokploy Logs ==="
    
    # Common Dokploy paths
    local dokploy_paths=(
        "/var/lib/dokploy"
        "/opt/dokploy"
        "$HOME/.dokploy"
    )
    
    local found=false
    for path in "${dokploy_paths[@]}"; do
        if [ -d "$path" ]; then
            found=true
            find "$path" -type f \( -name "*.log" -o -name "*.log.*" \) 2>/dev/null | while read -r logfile; do
                rotate_and_trim_logs "$logfile" "$LOG_SIZE_LIMIT_BYTES"
            done
        fi
    done
    
    if [ "$found" = "false" ]; then
        log_warning "Dokploy directories not found"
    fi
}

cleanup_system_logs() {
    log "=== Cleaning System Logs ==="
    
    # Rotate journal logs (keep last 100MB)
    if command -v journalctl &> /dev/null; then
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would vacuum journalctl to 100M"
        else
            journalctl --vacuum-size=100M 2>/dev/null && log_success "Vacuumed journalctl" || log_warning "Journalctl vacuum failed"
        fi
    fi
    
    # Clean old system logs
    local system_log_paths=(
        "/var/log/syslog.*"
        "/var/log/kern.log.*"
        "/var/log/auth.log.*"
        "/var/log/nginx/*.log.*"
        "/var/log/apache2/*.log.*"
        "/var/log/mysql/*.log.*"
        "/var/log/postgresql/*.log.*"
    )
    
    for pattern in "${system_log_paths[@]}"; do
        find $(dirname "$pattern") -name "$(basename "$pattern")" -type f -mtime +3 2>/dev/null | while read -r oldlog; do
            safe_delete "$oldlog"
        done
    done
    
    # Trim current active logs
    local active_logs=(
        "/var/log/syslog"
        "/var/log/kern.log"
        "/var/log/auth.log"
    )
    
    for logfile in "${active_logs[@]}"; do
        if [ -f "$logfile" ]; then
            rotate_and_trim_logs "$logfile" "$((LOG_SIZE_LIMIT_BYTES * 2))"  # Keep 20MB for system logs
        fi
    done
}

cleanup_apt_cache() {
    log "=== Cleaning APT Cache ==="
    
    if command -v apt-get &> /dev/null; then
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would clean apt cache"
        else
            apt-get clean 2>/dev/null && log_success "Cleaned apt cache" || log_warning "APT clean failed"
            apt-get autoclean 2>/dev/null && log_success "Auto-cleaned apt" || log_warning "APT autoclean failed"
            apt-get autoremove -y 2>/dev/null && log_success "Removed unused packages" || log_warning "APT autoremove failed"
        fi
    fi
}

cleanup_temp_files() {
    log "=== Cleaning Temporary Files ==="
    
    local temp_paths=(
        "/tmp/*"
        "/var/tmp/*"
    )
    
    for pattern in "${temp_paths[@]}"; do
        # Only delete files older than 2 days for safety
        find $(dirname "$pattern") -maxdepth 1 -type f -mtime +2 2>/dev/null | while read -r tmpfile; do
            safe_delete "$tmpfile"
        done
    done
}

cleanup_npm_cache() {
    log "=== Cleaning NPM Cache ==="
    
    if command -v npm &> /dev/null; then
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would clean npm cache"
        else
            npm cache clean --force 2>/dev/null && log_success "Cleaned npm cache" || log_warning "NPM cache clean failed"
        fi
    fi
}

cleanup_yarn_cache() {
    log "=== Cleaning Yarn Cache ==="
    
    if command -v yarn &> /dev/null; then
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would clean yarn cache"
        else
            yarn cache clean 2>/dev/null && log_success "Cleaned yarn cache" || log_warning "Yarn cache clean failed"
        fi
    fi
}

cleanup_pip_cache() {
    log "=== Cleaning Pip Cache ==="
    
    if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
        local pip_cmd=$(command -v pip3 2>/dev/null || command -v pip 2>/dev/null)
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would clean pip cache"
        else
            $pip_cmd cache purge 2>/dev/null && log_success "Cleaned pip cache" || log_warning "Pip cache purge failed"
        fi
    fi
}

cleanup_thumbnail_cache() {
    log "=== Cleaning Thumbnail Cache ==="
    
    local thumbnail_paths=(
        "$HOME/.cache/thumbnails"
        "$HOME/.thumbnails"
    )
    
    for cache_path in "${thumbnail_paths[@]}"; do
        if [ -d "$cache_path" ]; then
            safe_delete "$cache_path"
        fi
    done
}

cleanup_old_kernels() {
    log "=== Cleaning Old Kernels ==="
    
    if command -v apt-get &> /dev/null; then
        local current_kernel=$(uname -r)
        log "Current kernel: $current_kernel (will be preserved)"
        
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "[DRY RUN] Would remove old kernels (keeping current: $current_kernel)"
            dpkg -l | grep -E 'linux-image-[0-9]' | grep -v "$current_kernel" | awk '{print $2}' || true
        else
            # This is conservative - only suggests removal, doesn't auto-remove
            log_warning "Old kernels found (manual review recommended):"
            dpkg -l | grep -E 'linux-image-[0-9]' | grep -v "$current_kernel" | awk '{print $2}' || true
        fi
    fi
}

################################################################################
# Main Execution
################################################################################

main() {
    log "========================================="
    log "VPS Cleanup Script Started"
    log "========================================="
    
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        log_error "This script must be run as root"
        exit 1
    fi
    
    local disk_before=$(get_disk_usage)
    log "Disk usage before: $disk_before"
    echo ""
    
    # Run all cleanup functions
    cleanup_pm2_logs
    echo ""
    
    cleanup_docker_logs
    echo ""
    
    cleanup_dokploy_logs
    echo ""
    
    cleanup_system_logs
    echo ""
    
    cleanup_apt_cache
    echo ""
    
    cleanup_temp_files
    echo ""
    
    cleanup_npm_cache
    echo ""
    
    cleanup_yarn_cache
    echo ""
    
    cleanup_pip_cache
    echo ""
    
    cleanup_thumbnail_cache
    echo ""
    
    cleanup_old_kernels
    echo ""
    
    local disk_after=$(get_disk_usage)
    log "========================================="
    log "VPS Cleanup Script Completed"
    log "Disk usage before: $disk_before"
    log "Disk usage after:  $disk_after"
    log "========================================="
}

# Run main function
main "$@"
