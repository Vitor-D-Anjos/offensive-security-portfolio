# Network Enumeration Script
# Lateral Movement Assessment - Internal Penetration Test
# Author: Penetration Testing Team
# Date: October 2024

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Banner
echo "=========================================="
echo "  Network Enumeration Script"
echo "  Lateral Movement Assessment"
echo "=========================================="
echo

# Configuration
TARGET_NETWORK="${1:-192.168.78.0/24}"
OUTPUT_DIR="${2:-./scan_results}"
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')

# Create output directory
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

# Phase 1: Host Discovery
log "Starting Phase 1: Host Discovery"
info "Target network: $TARGET_NETWORK"

log "Running TCP SYN ping scan..."
nmap -sn -PE -PS22,80,443 -PA21,25,3389 "$TARGET_NETWORK" -oA "$OUTPUT_DIR/host_discovery_tcp_$TIMESTAMP"

log "Running UDP ping scan..."
nmap -sn -PU "$TARGET_NETWORK" -oA "$OUTPUT_DIR/host_discovery_udp_$TIMESTAMP"

# Parse live hosts
LIVE_HOSTS=$(grep "Up" "$OUTPUT_DIR/host_discovery_tcp_$TIMESTAMP.gnmap" | awk '{print $2}' | tr '\n' ' ')
log "Live hosts discovered: $LIVE_HOSTS"

if [ -z "$LIVE_HOSTS" ]; then
    error "No live hosts found. Exiting."
    exit 1
fi

# Phase 2: Comprehensive Port Scanning
log "Starting Phase 2: Port Scanning"

log "Running TCP SYN scan on all ports..."
nmap -sS -T4 -p- --min-rate 5000 "$TARGET_NETWORK" -oA "$OUTPUT_DIR/tcp_full_scan_$TIMESTAMP"

log "Running service version detection..."
nmap -sS -sV -sC -O -T4 -p 21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5985,5986 $LIVE_HOSTS -oA "$OUTPUT_DIR/service_scan_$TIMESTAMP"

# Phase 3: Service-specific Enumeration
log "Starting Phase 3: Service-specific Enumeration"

for host in $LIVE_HOSTS; do
    log "Enumerating services on $host"
    
    # Check for SMB
    if nmap -p 445 --open $host | grep -q "open"; then
        log "SMB found on $host, running enumeration..."
        nmap --script smb-os-discovery,smb-security-mode,smb-enum-shares,smb-enum-users -p 445 $host -oA "$OUTPUT_DIR/smb_enum_${host}_$TIMESTAMP"
    fi
    
    # Check for SSH
    if nmap -p 22 --open $host | grep -q "open"; then
        log "SSH found on $host, gathering banner..."
        nc -nv -w 2 $host 22 > "$OUTPUT_DIR/ssh_banner_${host}_$TIMESTAMP.txt" 2>&1 || true
    fi
    
    # Check for RDP
    if nmap -p 3389 --open $host | grep -q "open"; then
        log "RDP found on $host, checking security..."
        nmap --script rdp-enum-encryption,rdp-ntlm-info -p 3389 $host -oA "$OUTPUT_DIR/rdp_enum_${host}_$TIMESTAMP"
    fi
    
    # Check for HTTP/HTTPS
    for port in 80 443 8080 8443; do
        if nmap -p $port --open $host | grep -q "open"; then
            log "HTTP(S) found on $host:$port, running web scripts..."
            nmap --script http-title,http-headers,http-methods -p $port $host -oA "$OUTPUT_DIR/web_${port}_${host}_$TIMESTAMP"
            
            # Quick directory check
            if command -v gobuster &> /dev/null; then
                log "Running quick directory scan on $host:$port"
                gobuster dir -u "http://$host:$port" -w /usr/share/wordlists/dirb/common.txt -t 20 -o "$OUTPUT_DIR/gobuster_${port}_${host}_$TIMESTAMP.txt" 2>/dev/null &
            fi
        fi
    done
done

# Phase 4: Network Mapping
log "Starting Phase 4: Network Topology Mapping"

log "Running traceroute to key hosts..."
for host in $LIVE_HOSTS; do
    traceroute -m 15 -w 1 $host > "$OUTPUT_DIR/traceroute_${host}_$TIMESTAMP.txt" 2>&1 &
done
wait

# Phase 5: Vulnerability Scanning
log "Starting Phase 5: Vulnerability Assessment"

log "Running NSE vulnerability scripts..."
nmap --script vuln -T4 $LIVE_HOSTS -oA "$OUTPUT_DIR/vuln_scan_$TIMESTAMP"

# Generate summary report
log "Generating summary report..."
{
    echo "Network Enumeration Summary Report"
    echo "=================================="
    echo "Date: $(date)"
    echo "Target Network: $TARGET_NETWORK"
    echo "Live Hosts: $LIVE_HOSTS"
    echo
    echo "Scan Files:"
    find "$OUTPUT_DIR" -name "*$TIMESTAMP*" -type f | while read file; do
        echo "  - $(basename "$file")"
    done
    echo
    echo "Key Findings:"
    echo "============="
    
    # Extract key information
    echo "Open Services Summary:"
    grep -h "open" "$OUTPUT_DIR/service_scan_$TIMESTAMP.nmap" | sort | uniq
    
} > "$OUTPUT_DIR/summary_report_$TIMESTAMP.txt"

log "Enumeration completed successfully"
info "Results saved to: $OUTPUT_DIR"
info "Summary report: $OUTPUT_DIR/summary_report_$TIMESTAMP.txt"

echo
echo "Next steps:"
echo "1. Review service_scan_$TIMESTAMP.nmap for service details"
echo "2. Check vuln_scan_$TIMESTAMP.nmap for potential vulnerabilities"
echo "3. Analyze SMB and web enumeration results for attack vectors"
