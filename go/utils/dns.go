package utils

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func QueryTTL(query, resolver string) (int, error) {
	host, _, _ := net.SplitHostPort(resolver)
	if host == "" {
		host = resolver
	}

	cmd := exec.Command("dig", query, "@"+host, "+noall", "+answer", "+authority")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(`^\S+\s+(\d+)`)
	for _, line := range lines {
		match := re.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) > 1 {
			ttl, _ := strconv.Atoi(match[1])
			return ttl, nil
		}
	}

	return 0, fmt.Errorf("TTL not found in output")
}

func TriggerQuery(query, resolver string) {
	host, _, _ := net.SplitHostPort(resolver)
	if host == "" {
		host = resolver
	}
	exec.Command("dig", query, "@"+host, "+short").Run()
}