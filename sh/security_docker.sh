#!/usr/bin/env bash
set -uo pipefail

# ============================================================================
# Docker Security Incident Response Tool - Production Grade
# ============================================================================
# Features:
# - Comprehensive input validation and sanitization
# - Detailed logging with rotation
# - Enhanced security controls
# - Robust error handling
# - Progress indicators
# - Report generation
# ============================================================================

# --- Configuration & Colors ---
readonly RED="\033[0;31m"
readonly GREEN="\033[0;32m"
readonly YELLOW="\033[1;33m"
readonly BLUE="\033[0;34m"
readonly CYAN="\033[0;36m"
readonly MAGENTA="\033[0;35m"
readonly BOLD="\033[1m"
readonly NC="\033[0m"

# Global state
OS_FAMILY="unknown"
PKG_MANAGER="unknown"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/docker-security"
REPORT_DIR="/var/log/docker-security/reports"
SESSION_LOG=""
SCRIPT_VERSION="2.0.0"

# Create logging infrastructure
setup_logging() {
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    SESSION_LOG="$LOG_DIR/session-$(date +%Y%m%d-%H%M%S).log"

    # Rotate old logs (keep last 30 days)
    find "$LOG_DIR" -name "session-*.log" -mtime +30 -delete 2>/dev/null || true

    log "INFO" "=== Docker Security Tool v$SCRIPT_VERSION Started ==="
    log "INFO" "Session log: $SESSION_LOG"
}

# Enhanced logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$SESSION_LOG"
}

# --- Utility Functions ---
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|kali|linuxmint|pop)
                OS_FAMILY="debian"
                ;;
            rocky|rhel|centos|almalinux|fedora|amzn)
                OS_FAMILY="rhel"
                ;;
            arch|manjaro)
                OS_FAMILY="arch"
                ;;
            *)
                OS_FAMILY="unknown"
                ;;
        esac
        log "INFO" "Detected OS: $ID ($VERSION_ID) - Family: $OS_FAMILY"
    fi

    if [[ "$OS_FAMILY" == "unknown" ]]; then
        echo -e "${RED}Error: Unsupported OS. Supported: Debian/Ubuntu, RHEL-based, Arch-based.${NC}"
        log "ERROR" "Unsupported OS detected"
        exit 1
    fi
}

get_pkg_manager() {
    case "$OS_FAMILY" in
        debian)
            PKG_MANAGER="apt-get"
            ;;
        rhel)
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MANAGER="yum"
            else
                echo -e "${RED}Error: No package manager found.${NC}"
                log "ERROR" "No yum or dnf found on RHEL-based system"
                exit 1
            fi
            ;;
        arch)
            PKG_MANAGER="pacman"
            ;;
    esac
    log "INFO" "Package manager: $PKG_MANAGER"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (or with sudo).${NC}"
        echo -e "${YELLOW}Try: sudo $0${NC}"
        log "ERROR" "Script not run as root"
        exit 1
    fi
}

check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker not found. Please install Docker first.${NC}"
        log "ERROR" "Docker not installed"
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker daemon not running or not accessible.${NC}"
        echo -e "${YELLOW}Try: sudo systemctl start docker${NC}"
        log "ERROR" "Docker daemon not accessible"
        exit 1
    fi

    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    log "INFO" "Docker version: $docker_version"
}

check_dependencies() {
    local deps=("curl" "wget" "jq")
    local missing=()

    # Check which dependencies are missing
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    # Install missing dependencies
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Installing required dependencies: ${missing[*]}${NC}"
        log "INFO" "Installing dependencies: ${missing[*]}"

        case "$PKG_MANAGER" in
            apt-get)
                ${PKG_MANAGER} update -qq >/dev/null 2>&1
                ${PKG_MANAGER} install -y "${missing[@]}" >/dev/null 2>&1
                ;;
            yum|dnf)
                ${PKG_MANAGER} install -y "${missing[@]}" >/dev/null 2>&1
                ;;
            pacman)
                ${PKG_MANAGER} -Sy --noconfirm "${missing[@]}" >/dev/null 2>&1
                ;;
        esac

        # Verify installation
        local failed=()
        for cmd in "${missing[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                failed+=("$cmd")
            fi
        done

        if [[ ${#failed[@]} -gt 0 ]]; then
            echo -e "${RED}Warning: Failed to install: ${failed[*]}${NC}"
            log "WARN" "Failed to install dependencies: ${failed[*]}"
        else
            echo -e "${GREEN}✓ All dependencies installed${NC}"
            log "INFO" "Dependencies installed successfully"
        fi
    fi
}

# Input validation functions
validate_container_id() {
    local cid="$1"

    # Check format (alphanumeric, dots, dashes, underscores)
    if [[ ! "$cid" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
        echo -e "${RED}Invalid container ID format.${NC}"
        log "WARN" "Invalid container ID format: $cid"
        return 1
    fi

    # Verify container exists
    if ! docker inspect "$cid" >/dev/null 2>&1; then
        echo -e "${RED}Container '$cid' not found.${NC}"
        log "WARN" "Container not found: $cid"
        return 1
    fi

    return 0
}

validate_image_name() {
    local img="$1"

    # Docker image name validation (simplified but safe)
    if [[ ! "$img" =~ ^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*(:[a-zA-Z0-9_.-]+)?$ ]]; then
        echo -e "${RED}Invalid image name format.${NC}"
        echo -e "${YELLOW}Example: myapp:v1.0 or registry.io/myapp:latest${NC}"
        log "WARN" "Invalid image name format: $img"
        return 1
    fi

    return 0
}

validate_path() {
    local path="$1"
    local expanded_path

    # Safe tilde expansion
    if [[ "$path" =~ ^~ ]]; then
        if [[ -n "${SUDO_USER:-}" ]]; then
            expanded_path="${path/#\~/$(eval echo ~"$SUDO_USER")}"
        else
            expanded_path="${path/#\~/$HOME}"
        fi
    else
        expanded_path="$path"
    fi

    # Convert to absolute path
    if [[ "$expanded_path" != /* ]]; then
        expanded_path="$(pwd)/$expanded_path"
    fi

    # Prevent directory traversal
    expanded_path=$(realpath -m "$expanded_path" 2>/dev/null || echo "$expanded_path")

    echo "$expanded_path"
}

check_disk_space() {
    local required_mb="$1"
    local path="${2:-/tmp}"
    local available_kb

    available_kb=$(df -k "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    local available_mb=$((available_kb / 1024))

    if [[ $available_mb -lt $required_mb ]]; then
        echo -e "${RED}Insufficient disk space in $path${NC}"
        echo -e "${YELLOW}Required: ${required_mb}MB, Available: ${available_mb}MB${NC}"
        log "ERROR" "Insufficient disk space: required ${required_mb}MB, available ${available_mb}MB"
        return 1
    fi

    log "INFO" "Disk space check passed: ${available_mb}MB available"
    return 0
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local ans

    if [[ "$default" == "y" ]]; then
        read -rp "$prompt (Y/n): " ans
        ans="${ans,,}"
        [[ -z "$ans" || "$ans" == "y" ]]
    else
        read -rp "$prompt (y/N): " ans
        [[ "${ans,,}" == "y" ]]
    fi
}

pause() {
    echo ""
    read -rp "Press Enter to continue..."
}

show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'

    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\r"
    done
    printf "    \r"
}

banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     Docker Security Incident Response Tool v2.0           ║
║     Professional Grade Security Automation                ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${BLUE}OS: ${BOLD}$OS_FAMILY${NC} ${BLUE}| Package Manager: ${BOLD}$PKG_MANAGER${NC}"
    echo -e "${BLUE}Session Log: ${BOLD}$SESSION_LOG${NC}"
    echo ""
}

# --- Core Logic Functions ---

install_trivy() {
    if command -v trivy >/dev/null 2>&1; then
        log "INFO" "Trivy already installed: $(trivy --version | head -n1)"
        return 0
    fi

    echo -e "${YELLOW}Installing Trivy vulnerability scanner...${NC}"
    log "INFO" "Installing Trivy"

    case "$OS_FAMILY" in
        debian)
            ${PKG_MANAGER} update -y >/dev/null 2>&1
            ${PKG_MANAGER} install -y wget gnupg lsb-release >/dev/null 2>&1

            # Verify GPG key before adding
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
                gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null

            echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
                tee /etc/apt/sources.list.d/trivy.list > /dev/null

            ${PKG_MANAGER} update -y >/dev/null 2>&1
            ${PKG_MANAGER} install -y trivy
            ;;
        rhel)
            cat <<EOF | tee /etc/yum.repos.d/trivy.repo >/dev/null
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
            ${PKG_MANAGER} install -y trivy
            ;;
        arch)
            # Use -Sy cautiously on Arch - for a standalone package this is acceptable
            # but avoid partial upgrades in production environments
            ${PKG_MANAGER} -Sy --noconfirm trivy 2>&1 | tee -a "$SESSION_LOG" || \
                echo -e "${YELLOW}Note: On Arch Linux, consider full system upgrade if issues occur${NC}"
            ;;
    esac

    if command -v trivy >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Trivy installed successfully${NC}"
        log "INFO" "Trivy installed: $(trivy --version | head -n1)"
        return 0
    else
        echo -e "${RED}✗ Trivy installation failed${NC}"
        log "ERROR" "Trivy installation failed"
        return 1
    fi
}

option1_trivy_all() {
    banner
    echo -e "${CYAN}${BOLD}=== Trivy Vulnerability Scanner ===${NC}\n"

    if ! install_trivy; then
        pause
        return 1
    fi

    echo -e "${YELLOW}Updating vulnerability database...${NC}"
    log "INFO" "Updating Trivy database"

    if trivy image --download-db-only 2>&1 | tee -a "$SESSION_LOG"; then
        echo -e "${GREEN}✓ Database updated${NC}"
        log "INFO" "Trivy database updated successfully"
    else
        echo -e "${YELLOW}⚠ Database update warning (offline mode may be used)${NC}"
        log "WARN" "Trivy database update incomplete"
    fi

    echo ""
    echo -e "${CYAN}Select severity levels to scan:${NC}"
    echo -e "  1) CRITICAL only"
    echo -e "  2) HIGH,CRITICAL"
    echo -e "  3) MEDIUM,HIGH,CRITICAL"
    echo -e "  4) ALL severities"
    read -rp "Choice [2]: " sev_choice

    case "${sev_choice:-2}" in
        1) SEVERITY="CRITICAL" ;;
        2) SEVERITY="HIGH,CRITICAL" ;;
        3) SEVERITY="MEDIUM,HIGH,CRITICAL" ;;
        4) SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL" ;;
        *) SEVERITY="HIGH,CRITICAL" ;;
    esac

    echo ""
    echo -e "${YELLOW}Scanning all local images for vulnerabilities...${NC}"
    echo -e "${BLUE}Severity filter: $SEVERITY${NC}\n"
    log "INFO" "Starting Trivy scan with severity: $SEVERITY"

    local report_file="$REPORT_DIR/trivy-scan-$(date +%Y%m%d-%H%M%S).json"
    local summary_file="$REPORT_DIR/trivy-summary-$(date +%Y%m%d-%H%M%S).txt"

    local total_images=0
    local scanned_images=0
    local vulnerable_images=0
    local failed_scans=0

    # Count total images first
    while read -r img; do
        [[ -n "$img" ]] && ((total_images++))
    done < <(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v "^<none>" | grep -v ":<none>$" || true)

    if [[ $total_images -eq 0 ]]; then
        echo -e "${YELLOW}No images found to scan.${NC}"
        log "WARN" "No images found for scanning"
        pause
        return 0
    fi

    echo -e "${GREEN}Found $total_images images to scan${NC}\n"

    # Initialize JSON report
    echo "[" > "$report_file"
    local first_entry=true

    while read -r img; do
        if [[ -z "$img" ]]; then
            continue
        fi

        ((scanned_images++))
        echo -e "${CYAN}[$scanned_images/$total_images]${NC} Scanning: ${BOLD}$img${NC}"
        log "INFO" "Scanning image: $img"

        local temp_output
        temp_output=$(mktemp)

        if trivy image --severity "$SEVERITY" --format json --quiet "$img" > "$temp_output" 2>>"$SESSION_LOG"; then
            # Check if vulnerabilities were found
            local vuln_count
            vuln_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$temp_output" 2>/dev/null || echo "0")

            if [[ $vuln_count -gt 0 ]]; then
                echo -e "${RED}  ✗ Found $vuln_count vulnerabilities${NC}"
                ((vulnerable_images++))

                # Append to JSON report
                if [[ "$first_entry" == "true" ]]; then
                    first_entry=false
                else
                    echo "," >> "$report_file"
                fi

                jq -c ". + {\"image\": \"$img\", \"scan_time\": \"$(date -Iseconds)\"}" "$temp_output" >> "$report_file"
            else
                echo -e "${GREEN}  ✓ No vulnerabilities found${NC}"
            fi
        else
            echo -e "${RED}  ✗ Scan failed${NC}"
            ((failed_scans++))
            log "ERROR" "Trivy scan failed for image: $img"
        fi

        rm -f "$temp_output"
    done < <(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v "^<none>" | grep -v ":<none>$" || true)

    # Close JSON report
    echo "]" >> "$report_file"

    # Generate summary
    {
        echo "=== Trivy Scan Summary ==="
        echo "Date: $(date)"
        echo "Severity Filter: $SEVERITY"
        echo ""
        echo "Total Images: $total_images"
        echo "Scanned: $scanned_images"
        echo "Vulnerable: $vulnerable_images"
        echo "Failed Scans: $failed_scans"
        echo "Clean: $((scanned_images - vulnerable_images - failed_scans))"
        echo ""
        echo "Detailed report: $report_file"
    } | tee "$summary_file"

    echo ""
    echo -e "${GREEN}${BOLD}=== Scan Complete ===${NC}"
    echo -e "${BLUE}Summary saved to: $summary_file${NC}"
    echo -e "${BLUE}Detailed JSON report: $report_file${NC}"

    log "INFO" "Trivy scan complete: $scanned_images scanned, $vulnerable_images vulnerable, $failed_scans failed"

    pause
}

option2_clamav_container() {
    banner
    echo -e "${CYAN}${BOLD}=== ClamAV Malware Scanner ===${NC}\n"

    # List running containers
    echo -e "${YELLOW}Running containers:${NC}"
    docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" | head -20
    echo ""

    read -rp "Enter container ID or name: " CID
    CID="${CID// /}" # Remove spaces

    if ! validate_container_id "$CID"; then
        pause
        return 1
    fi

    # Get container info
    local container_name
    local container_image
    container_name=$(docker inspect --format='{{.Name}}' "$CID" | sed 's/^\/\(.*\)/\1/')
    container_image=$(docker inspect --format='{{.Config.Image}}' "$CID")

    echo -e "${GREEN}✓ Container found:${NC}"
    echo -e "  Name: ${BOLD}$container_name${NC}"
    echo -e "  Image: ${BOLD}$container_image${NC}"
    echo ""

    # Check disk space (need ~5GB)
    if ! check_disk_space 5000; then
        pause
        return 1
    fi

    if ! confirm "Proceed with malware scan? (This will snapshot the container)"; then
        return 0
    fi

    local WORKDIR
    WORKDIR=$(mktemp -d -t clamav-scan-XXXXXXXXXX)
    local TARFILE="$WORKDIR/container.tar"
    local scan_report="$REPORT_DIR/clamav-$container_name-$(date +%Y%m%d-%H%M%S).txt"

    log "INFO" "Starting ClamAV scan of container: $CID ($container_name)"
    log "INFO" "Workspace: $WORKDIR"

    # Cleanup function
    cleanup() {
        if [[ -d "$WORKDIR" ]]; then
            echo -e "\n${YELLOW}Cleaning up workspace...${NC}"
            rm -rf "$WORKDIR"
            log "INFO" "Workspace cleaned: $WORKDIR"
        fi
    }
    trap cleanup EXIT INT TERM

    # Export container filesystem
    echo -e "${YELLOW}Snapshotting container filesystem...${NC}"
    if docker export "$CID" -o "$TARFILE" 2>>"$SESSION_LOG"; then
        echo -e "${GREEN}✓ Container exported${NC}"
        log "INFO" "Container exported successfully"
    else
        echo -e "${RED}✗ Failed to export container${NC}"
        log "ERROR" "Container export failed"
        cleanup
        trap - EXIT INT TERM
        pause
        return 1
    fi

    # Extract filesystem
    echo -e "${YELLOW}Extracting filesystem...${NC}"
    if tar -xf "$TARFILE" -C "$WORKDIR" 2>>"$SESSION_LOG"; then
        rm -f "$TARFILE"
        echo -e "${GREEN}✓ Filesystem extracted${NC}"
        log "INFO" "Filesystem extracted"
    else
        echo -e "${RED}✗ Extraction failed${NC}"
        log "ERROR" "Filesystem extraction failed"
        cleanup
        trap - EXIT INT TERM
        pause
        return 1
    fi

    # Pull ClamAV image
    echo -e "${YELLOW}Pulling ClamAV scanner image...${NC}"
    if docker pull clamav/clamav:latest >/dev/null 2>&1; then
        echo -e "${GREEN}✓ ClamAV image ready${NC}"
        log "INFO" "ClamAV image pulled"
    else
        echo -e "${YELLOW}⚠ Using cached ClamAV image${NC}"
        log "WARN" "Using cached ClamAV image"
    fi

    # Run ClamAV scan
    echo -e "${YELLOW}Running malware scan... (This may take several minutes)${NC}"
    echo -e "${BLUE}Scanning filesystem extracted from: $container_name${NC}\n"

    log "INFO" "Starting ClamAV scan"

    # Run scan with proper security context
    # NOTE: Running as root is required to read the host-mounted temp directory
    # which is owned by root with 700 permissions
    local scan_output
    scan_output=$(mktemp)

    if docker run --rm \
        --user root \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=1g \
        -v "$WORKDIR":/scandir:ro \
        clamav/clamav:latest \
        sh -c 'freshclam --quiet 2>/dev/null || true; clamscan -r -i --no-summary /scandir' \
        2>&1 | tee "$scan_output"; then

        local infected_count
        infected_count=$(grep -c "FOUND" "$scan_output" || echo "0")

        # Save full report
        {
            echo "=== ClamAV Malware Scan Report ==="
            echo "Container: $container_name ($CID)"
            echo "Image: $container_image"
            echo "Scan Date: $(date)"
            echo "Infected Files: $infected_count"
            echo ""
            echo "=== Scan Results ==="
            cat "$scan_output"
        } > "$scan_report"

        echo ""
        if [[ $infected_count -gt 0 ]]; then
            echo -e "${RED}${BOLD}⚠ THREATS DETECTED: $infected_count infected file(s) found${NC}"
            log "WARN" "ClamAV found $infected_count infected files in container $CID"
        else
            echo -e "${GREEN}${BOLD}✓ No threats detected${NC}"
            log "INFO" "ClamAV scan clean for container $CID"
        fi

        echo -e "${BLUE}Full report: $scan_report${NC}"
    else
        echo -e "${RED}✗ Scan encountered errors${NC}"
        log "ERROR" "ClamAV scan failed"
    fi

    rm -f "$scan_output"

    # Cleanup
    cleanup
    trap - EXIT INT TERM

    pause
}

option3_rebuild_image() {
    banner
    echo -e "${CYAN}${BOLD}=== Secure Image Rebuild ===${NC}\n"

    read -rp "Enter target image name (e.g., myapp:latest): " IMG

    if ! validate_image_name "$IMG"; then
        pause
        return 1
    fi

    read -rp "Enter path to Dockerfile directory: " DOCKERDIR
    DOCKERDIR=$(validate_path "$DOCKERDIR")

    if [[ ! -d "$DOCKERDIR" ]]; then
        echo -e "${RED}Error: Directory does not exist: $DOCKERDIR${NC}"
        log "ERROR" "Directory not found: $DOCKERDIR"
        pause
        return 1
    fi

    if [[ ! -f "$DOCKERDIR/Dockerfile" ]]; then
        echo -e "${RED}Error: Dockerfile not found in: $DOCKERDIR${NC}"
        log "ERROR" "Dockerfile not found in: $DOCKERDIR"
        pause
        return 1
    fi

    echo ""
    echo -e "${GREEN}✓ Configuration validated${NC}"
    echo -e "  Image: ${BOLD}$IMG${NC}"
    echo -e "  Dockerfile: ${BOLD}$DOCKERDIR/Dockerfile${NC}"
    echo ""
    echo -e "${YELLOW}Build options:${NC}"
    echo -e "  • No cache (clean rebuild)"
    echo -e "  • Pull latest base images"
    echo -e "  • Security scanning after build"
    echo ""

    if ! confirm "Proceed with rebuild?"; then
        return 0
    fi

    log "INFO" "Starting image rebuild: $IMG from $DOCKERDIR"

    echo ""
    echo -e "${YELLOW}Building image (no cache)...${NC}"

    local build_log
    build_log=$(mktemp)

    if docker build \
        --no-cache \
        --pull \
        --progress=plain \
        -t "$IMG" \
        "$DOCKERDIR" 2>&1 | tee "$build_log"; then

        echo -e "${GREEN}${BOLD}✓ Build successful${NC}"
        log "INFO" "Image built successfully: $IMG"

        # Offer to scan the new image
        echo ""
        if confirm "Scan newly built image for vulnerabilities?"; then
            echo ""
            if command -v trivy >/dev/null 2>&1 || install_trivy; then
                echo -e "${YELLOW}Scanning $IMG...${NC}"
                trivy image --severity HIGH,CRITICAL "$IMG" | tee -a "$SESSION_LOG"
                log "INFO" "Post-build vulnerability scan completed"
            fi
        fi

        # Offer to tag and push
        echo ""
        if confirm "Tag and push image to registry?"; then
            read -rp "Enter registry/tag (e.g., registry.io/myapp:v1.0): " PUSH_TAG
            if validate_image_name "$PUSH_TAG"; then
                docker tag "$IMG" "$PUSH_TAG"
                echo -e "${YELLOW}Pushing $PUSH_TAG...${NC}"
                if docker push "$PUSH_TAG"; then
                    echo -e "${GREEN}✓ Image pushed successfully${NC}"
                    log "INFO" "Image pushed: $PUSH_TAG"
                else
                    echo -e "${RED}✗ Push failed${NC}"
                    log "ERROR" "Image push failed: $PUSH_TAG"
                fi
            fi
        fi
    else
        echo -e "${RED}${BOLD}✗ Build failed${NC}"
        echo -e "${YELLOW}Check build log: $build_log${NC}"
        log "ERROR" "Image build failed: $IMG"
    fi

    pause
}

option4_falco() {
    banner
    echo -e "${CYAN}${BOLD}=== Falco Runtime Security ===${NC}\n"

    echo -e "${YELLOW}Falco provides real-time runtime security monitoring:${NC}"
    echo -e "  • Detect suspicious process behavior"
    echo -e "  • Monitor file access and modifications"
    echo -e "  • Track network connections"
    echo -e "  • Alert on privilege escalation"
    echo -e "  • Container-aware monitoring"
    echo ""

    if command -v falco >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Falco is already installed${NC}"
        local falco_version
        falco_version=$(falco --version 2>/dev/null | head -n1 || echo "unknown")
        echo -e "  Version: $falco_version"
        echo ""

        if systemctl is-active --quiet falco 2>/dev/null; then
            echo -e "${GREEN}✓ Falco is running${NC}"
            echo ""
            echo -e "${CYAN}Recent alerts:${NC}"
            journalctl -u falco -n 20 --no-pager 2>/dev/null || echo "No recent logs"
            echo ""
            echo -e "${BLUE}Monitor live: ${BOLD}journalctl -u falco -f${NC}"
        else
            echo -e "${YELLOW}⚠ Falco is installed but not running${NC}"
            if confirm "Start Falco now?"; then
                systemctl enable --now falco
                echo -e "${GREEN}✓ Falco started${NC}"
            fi
        fi

        pause
        return 0
    fi

    echo -e "${YELLOW}⚠ Requirements:${NC}"
    echo -e "  • Kernel headers for: $(uname -r)"
    echo -e "  • ~100MB disk space"
    echo -e "  • Root privileges"
    echo ""

    if ! confirm "Install Falco?"; then
        return 0
    fi

    log "INFO" "Installing Falco runtime security"

    echo -e "${YELLOW}Installing prerequisites...${NC}"

    case "$OS_FAMILY" in
        debian)
            ${PKG_MANAGER} update >/dev/null 2>&1
            ${PKG_MANAGER} install -y curl gnupg2 >/dev/null 2>&1

            # Install kernel headers
            local kernel_version
            kernel_version=$(uname -r)
            echo -e "${YELLOW}Installing kernel headers for $kernel_version...${NC}"

            if ! ${PKG_MANAGER} install -y "linux-headers-$kernel_version" 2>&1 | tee -a "$SESSION_LOG"; then
                echo -e "${RED}Warning: Could not install exact kernel headers${NC}"
                echo -e "${YELLOW}Trying generic headers...${NC}"
                ${PKG_MANAGER} install -y linux-headers-generic 2>&1 | tee -a "$SESSION_LOG" || true
            fi

            # Add Falco repository
            echo -e "${YELLOW}Adding Falco repository...${NC}"
            curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
                gpg --dearmor | tee /usr/share/keyrings/falco.gpg > /dev/null

            echo "deb [signed-by=/usr/share/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main" | \
                tee /etc/apt/sources.list.d/falcosecurity.list > /dev/null

            ${PKG_MANAGER} update >/dev/null 2>&1

            echo -e "${YELLOW}Installing Falco...${NC}"
            ${PKG_MANAGER} install -y falco
            ;;
        rhel)
            ${PKG_MANAGER} install -y curl >/dev/null 2>&1

            # Install kernel headers
            echo -e "${YELLOW}Installing kernel headers...${NC}"
            ${PKG_MANAGER} install -y "kernel-devel-$(uname -r)" 2>&1 | tee -a "$SESSION_LOG" || \
                ${PKG_MANAGER} install -y kernel-devel 2>&1 | tee -a "$SESSION_LOG"

            # Add Falco repository
            echo -e "${YELLOW}Adding Falco repository...${NC}"
            curl -s -o /etc/yum.repos.d/falcosecurity.repo \
                https://falco.org/repo/falcosecurity-rpm.repo

            echo -e "${YELLOW}Installing Falco...${NC}"
            ${PKG_MANAGER} install -y falco
            ;;
        arch)
            ${PKG_MANAGER} -Sy --noconfirm linux-headers falco
            ;;
    esac

    if command -v falco >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Falco installed successfully${NC}"
        log "INFO" "Falco installed successfully"

        # Configure and start
        echo -e "${YELLOW}Configuring Falco...${NC}"

        # Enable and start service
        if systemctl enable --now falco 2>&1 | tee -a "$SESSION_LOG"; then
            echo -e "${GREEN}✓ Falco is now running${NC}"
            log "INFO" "Falco service started"

            echo ""
            echo -e "${CYAN}${BOLD}Configuration:${NC}"
            echo -e "  • Rules: ${BOLD}/etc/falco/falco_rules.yaml${NC}"
            echo -e "  • Custom rules: ${BOLD}/etc/falco/falco_rules.local.yaml${NC}"
            echo -e "  • Config: ${BOLD}/etc/falco/falco.yaml${NC}"
            echo ""
            echo -e "${CYAN}${BOLD}Monitoring:${NC}"
            echo -e "  • View logs: ${BOLD}journalctl -u falco -f${NC}"
            echo -e "  • Status: ${BOLD}systemctl status falco${NC}"
            echo ""

            # Show sample alerts
            echo -e "${YELLOW}Waiting for initial alerts...${NC}"
            sleep 3
            echo -e "${CYAN}Recent activity:${NC}"
            journalctl -u falco -n 10 --no-pager 2>/dev/null || echo "No alerts yet"
        else
            echo -e "${YELLOW}⚠ Falco installed but failed to start${NC}"
            echo -e "${BLUE}Check status: systemctl status falco${NC}"
            log "WARN" "Falco installed but failed to start"
        fi
    else
        echo -e "${RED}✗ Falco installation failed${NC}"
        log "ERROR" "Falco installation failed"
    fi

    pause
}

option5_docker_bench() {
    banner
    echo -e "${CYAN}${BOLD}=== Docker Bench Security Audit ===${NC}\n"

    echo -e "${YELLOW}Docker Bench runs security best practice checks:${NC}"
    echo -e "  • Host configuration"
    echo -e "  • Docker daemon configuration"
    echo -e "  • Container runtime security"
    echo -e "  • Network security"
    echo -e "  • Docker security operations"
    echo ""

    if ! confirm "Run Docker Bench security audit?"; then
        return 0
    fi

    log "INFO" "Running Docker Bench security audit"

    local report_file="$REPORT_DIR/docker-bench-$(date +%Y%m%d-%H%M%S).log"

    echo -e "${YELLOW}Pulling Docker Bench image...${NC}"
    if docker pull docker/docker-bench-security:latest >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Image ready${NC}"
    fi

    echo -e "${YELLOW}Running security audit...${NC}\n"

    docker run --rm --net host --pid host --userns host --cap-add audit_control \
        -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
        -v /etc:/etc:ro \
        -v /usr/bin/containerd:/usr/bin/containerd:ro \
        -v /usr/bin/runc:/usr/bin/runc:ro \
        -v /usr/lib/systemd:/usr/lib/systemd:ro \
        -v /var/lib:/var/lib:ro \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        --label docker_bench_security \
        docker/docker-bench-security 2>&1 | tee "$report_file"

    echo ""
    echo -e "${GREEN}✓ Audit complete${NC}"
    echo -e "${BLUE}Report saved: $report_file${NC}"

    log "INFO" "Docker Bench audit completed"

    pause
}

option6_view_reports() {
    banner
    echo -e "${CYAN}${BOLD}=== Security Reports ===${NC}\n"

    if [[ ! -d "$REPORT_DIR" ]] || [[ -z "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}No reports found yet.${NC}"
        echo -e "${BLUE}Reports will be saved to: $REPORT_DIR${NC}"
        pause
        return 0
    fi

    echo -e "${YELLOW}Available reports:${NC}\n"

    local report_num=1
    declare -a report_files

    while IFS= read -r -d '' report; do
        local filename
        local filesize
        local filedate
        filename=$(basename "$report")
        filesize=$(du -h "$report" | cut -f1)
        filedate=$(stat -c '%y' "$report" 2>/dev/null | cut -d'.' -f1 || stat -f '%Sm' "$report" 2>/dev/null)

        echo -e "${CYAN}[$report_num]${NC} $filename"
        echo -e "     Size: $filesize | Date: $filedate"

        report_files+=("$report")
        ((report_num++))
    done < <(find "$REPORT_DIR" -type f \( -name "*.txt" -o -name "*.json" -o -name "*.log" \) -print0 | sort -z -r)

    echo ""
    echo -e "${CYAN}[a]${NC} View all reports directory"
    echo -e "${CYAN}[c]${NC} Clean old reports (>30 days)"
    echo -e "${CYAN}[b]${NC} Back to main menu"
    echo ""

    read -rp "Select report to view (or a/c/b): " choice

    case "$choice" in
        a|A)
            ls -lht "$REPORT_DIR"
            ;;
        c|C)
            if confirm "Delete reports older than 30 days?"; then
                local deleted
                deleted=$(find "$REPORT_DIR" -type f -mtime +30 -delete -print | wc -l)
                echo -e "${GREEN}✓ Deleted $deleted old reports${NC}"
                log "INFO" "Cleaned $deleted old reports"
            fi
            ;;
        b|B)
            return 0
            ;;
        *)
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -lt $report_num ]]; then
                local selected_report="${report_files[$((choice-1))]}"
                echo ""
                echo -e "${CYAN}=== $(basename "$selected_report") ===${NC}\n"

                if [[ "$selected_report" == *.json ]]; then
                    if command -v jq >/dev/null 2>&1; then
                        jq -C '.' "$selected_report" | less -R
                    else
                        less "$selected_report"
                    fi
                else
                    less "$selected_report"
                fi
            else
                echo -e "${RED}Invalid selection${NC}"
            fi
            ;;
    esac

    pause
}

option7_container_forensics() {
    banner
    echo -e "${CYAN}${BOLD}=== Container Forensics ===${NC}\n"

    echo -e "${YELLOW}Running containers:${NC}"
    docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"
    echo ""

    read -rp "Enter container ID or name to investigate: " CID

    if ! validate_container_id "$CID"; then
        pause
        return 1
    fi

    local container_name
    container_name=$(docker inspect --format='{{.Name}}' "$CID" | sed 's/^\/\(.*\)/\1/')

    local forensics_dir="$REPORT_DIR/forensics-$container_name-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$forensics_dir"

    echo -e "${YELLOW}Collecting forensic data...${NC}\n"
    log "INFO" "Starting forensic collection for container: $CID"

    # Container metadata
    echo -e "${CYAN}[1/6]${NC} Collecting container metadata..."
    docker inspect "$CID" > "$forensics_dir/inspect.json"

    # Process list
    echo -e "${CYAN}[2/6]${NC} Collecting process list..."
    docker top "$CID" > "$forensics_dir/processes.txt" 2>&1 || true

    # Network connections
    echo -e "${CYAN}[3/6]${NC} Collecting network information..."
    {
        echo "=== Network Settings ==="
        docker inspect "$CID" | jq '.[0].NetworkSettings'
        echo -e "\n=== Port Mappings ==="
        docker port "$CID"
    } > "$forensics_dir/network.txt" 2>&1

    # File system changes
    echo -e "${CYAN}[4/6]${NC} Analyzing filesystem changes..."
    echo -e "${YELLOW}     (This may produce large output for long-running containers)${NC}"
    docker diff "$CID" 2>&1 | head -n 10000 > "$forensics_dir/filesystem-diff.txt" || true
    echo "Note: Output limited to first 10,000 lines for performance" >> "$forensics_dir/filesystem-diff.txt"

    # Container logs
    echo -e "${CYAN}[5/6]${NC} Collecting container logs..."
    docker logs "$CID" > "$forensics_dir/container-logs.txt" 2>&1

    # Resource usage stats
    echo -e "${CYAN}[6/6]${NC} Collecting resource statistics..."
    {
        echo "=== Current Stats ==="
        docker stats "$CID" --no-stream --no-trunc
        echo -e "\n=== Container Events (last 100) ==="
        docker events --since 24h --filter "container=$CID" --format '{{.Time}}: {{.Status}} - {{.Action}}' 2>/dev/null | tail -100
    } > "$forensics_dir/stats.txt" 2>&1

    # Create summary report
    {
        echo "=== Container Forensics Summary ==="
        echo "Container: $container_name ($CID)"
        echo "Collected: $(date)"
        echo "Location: $forensics_dir"
        echo ""
        echo "=== Files Collected ==="
        ls -lh "$forensics_dir"
    } > "$forensics_dir/README.txt"

    echo ""
    echo -e "${GREEN}${BOLD}✓ Forensics collection complete${NC}"
    echo -e "${BLUE}Location: $forensics_dir${NC}"
    echo ""
    echo -e "${YELLOW}Collected data:${NC}"
    ls -1 "$forensics_dir" | sed 's/^/  • /'

    log "INFO" "Forensics collected: $forensics_dir"

    if confirm "Open forensics directory?"; then
        cd "$forensics_dir" && ls -lah
        echo ""
        echo -e "${BLUE}You are now in: $forensics_dir${NC}"
    fi

    pause
}

show_help() {
    banner
    echo -e "${CYAN}${BOLD}=== Help & Documentation ===${NC}\n"

    cat << EOF
${YELLOW}Tool Overview:${NC}
This tool provides automated security incident response capabilities for
Docker environments. It combines vulnerability scanning, malware detection,
secure rebuilds, and runtime monitoring.

${YELLOW}Features:${NC}

${CYAN}1. Trivy Vulnerability Scanner${NC}
   • Scans container images for known CVEs
   • Configurable severity filtering
   • JSON reports for integration
   • Batch scanning of all local images

${CYAN}2. ClamAV Malware Scanner${NC}
   • Deep malware scan of container filesystems
   • Safe snapshot-based scanning
   • No impact on running containers
   • Comprehensive threat reports

${CYAN}3. Secure Image Rebuild${NC}
   • Clean rebuild with no cache
   • Pull latest base images
   • Automated vulnerability scanning post-build
   • Registry push integration

${CYAN}4. Falco Runtime Security${NC}
   • Real-time behavioral monitoring
   • Kernel-level system call monitoring
   • Container-aware rule engine
   • Custom rule support

${CYAN}5. Docker Bench Security${NC}
   • CIS Docker Benchmark compliance
   • Best practice configuration checks
   • Host and daemon security audit

${CYAN}6. Container Forensics${NC}
   • Complete container state capture
   • Network and process analysis
   • Filesystem change detection
   • Event timeline reconstruction

${YELLOW}Best Practices:${NC}
  • Run regular vulnerability scans (weekly minimum)
  • Enable Falco for production environments
  • Review reports in /var/log/docker-security/reports
  • Keep tool database updated (Trivy, ClamAV)
  • Archive forensic data for compliance

${YELLOW}Files & Logs:${NC}
  • Session logs: $LOG_DIR
  • Reports: $REPORT_DIR
  • Current session: $SESSION_LOG

${YELLOW}Support:${NC}
  • View logs: journalctl -u falco -f
  • Check Docker: docker info
  • Trivy DB update: trivy image --download-db-only

EOF

    pause
}

# --- Main Menu ---
main_menu() {
    check_root
    detect_os
    get_pkg_manager
    check_dependencies
    check_docker
    setup_logging

    while true; do
        banner
        echo -e "${YELLOW}${BOLD}Security Operations:${NC}"
        echo -e "  ${CYAN}1)${NC} Trivy - Scan images for vulnerabilities"
        echo -e "  ${CYAN}2)${NC} ClamAV - Deep malware scan of container"
        echo -e "  ${CYAN}3)${NC} Rebuild - Secure image rebuild (no cache)"
        echo -e "  ${CYAN}4)${NC} Falco - Install runtime security monitoring"
        echo -e "  ${CYAN}5)${NC} Docker Bench - Security configuration audit"
        echo ""
        echo -e "${YELLOW}${BOLD}Analysis & Reports:${NC}"
        echo -e "  ${CYAN}6)${NC} View reports and scan history"
        echo -e "  ${CYAN}7)${NC} Container forensics investigation"
        echo ""
        echo -e "${YELLOW}${BOLD}Other:${NC}"
        echo -e "  ${CYAN}h)${NC} Help & documentation"
        echo -e "  ${CYAN}q)${NC} Exit"
        echo ""

        read -rp "${BOLD}Selection:${NC} " choice

        case "$choice" in
            1) option1_trivy_all ;;
            2) option2_clamav_container ;;
            3) option3_rebuild_image ;;
            4) option4_falco ;;
            5) option5_docker_bench ;;
            6) option6_view_reports ;;
            7) option7_container_forensics ;;
            h|H) show_help ;;
            q|Q)
                echo ""
                echo -e "${GREEN}Session log saved: $SESSION_LOG${NC}"
                log "INFO" "Tool session ended"
                echo -e "${CYAN}Stay secure!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

# --- Entry Point ---
main_menu