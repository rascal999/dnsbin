package main

import (
	"dnsbin/config"
	"dnsbin/exfil"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
)

var completer = readline.NewPrefixCompleter(
	readline.PcItem("set",
		readline.PcItem("domain"),
		readline.PcItem("resolver"),
		readline.PcItem("maxlen"),
		readline.PcItem("concurrency"),
		readline.PcItem("integrity",
			readline.PcItem("true"),
			readline.PcItem("false"),
		),
		readline.PcItem("debug",
			readline.PcItem("true"),
			readline.PcItem("false"),
		),
	),
	readline.PcItem("show",
		readline.PcItem("config"),
	),
	readline.PcItem("send"),
	readline.PcItem("receive"),
	readline.PcItem("help"),
	readline.PcItem("exit"),
)

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func main() {
	cfg := config.Load()

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31mdnsbin\033[0m> ",
		HistoryFile:     "/tmp/dnsbin.tmp",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()
	l.CaptureExitSignal()

	log.SetOutput(l.Stderr())

	for {
		line, err := l.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		args := strings.Split(line, " ")
		cmd := args[0]

		switch cmd {
		case "help":
			usage()
		case "exit":
			return
		case "show":
			if len(args) > 1 && args[1] == "config" {
				fmt.Printf("\rDomain:      %s\r\n", cfg.Domain)
				fmt.Printf("Resolver:    %s\r\n", cfg.Resolver)
				fmt.Printf("MaxLen:      %d\r\n", cfg.MaxLen)
				fmt.Printf("Concurrency: %d\r\n", cfg.Concurrency)
				fmt.Printf("Integrity:   %v (CRC32 256b blocks)\r\n", (cfg.Options&(1<<2)) != 0)
				fmt.Printf("Debug:       %v\r\n", cfg.Debug)
			} else {
				fmt.Println("Usage: show config\r")
			}
		case "set":
			if len(args) < 3 {
				fmt.Print("\rUsage: set <domain|resolver> <value>\r\n")
				continue
			}
			key := args[1]
			val := args[2]
			if key == "domain" {
				cfg.Domain = val
				config.Save(cfg)
				fmt.Printf("\r\033[32m[+]\033[0m Domain updated to: %s\r\n", cfg.Domain)
			} else if key == "resolver" {
				if !strings.Contains(val, ":") {
					val += ":53"
				}
				cfg.Resolver = val
				config.Save(cfg)
				fmt.Printf("\r\033[32m[+]\033[0m Resolver updated to: %s\r\n", cfg.Resolver)
			} else if key == "debug" {
				cfg.Debug = (val == "true")
				config.Save(cfg)
				fmt.Printf("\r\033[32m[+]\033[0m Debug mode set to: %v\r\n", cfg.Debug)
			} else if key == "maxlen" {
				if v, err := strconv.Atoi(val); err == nil {
					cfg.MaxLen = v
					config.Save(cfg)
					fmt.Printf("\r\033[32m[+]\033[0m Max receive length set to: %d\r\n", cfg.MaxLen)
				} else {
					fmt.Print("\r\033[31m[!!]\033[0m Invalid number for maxlen\r\n")
				}
			} else if key == "concurrency" {
				if v, err := strconv.Atoi(val); err == nil {
					cfg.Concurrency = v
					config.Save(cfg)
					fmt.Printf("\r\033[32m[+]\033[0m Concurrency set to: %d\r\n", cfg.Concurrency)
				} else {
					fmt.Print("\r\033[31m[!!]\033[0m Invalid number for concurrency\r\n")
				}
			} else if key == "integrity" {
				if val == "true" {
					cfg.Options |= (1 << 2)
				} else {
					cfg.Options &= ^byte(1 << 2)
				}
				config.Save(cfg)
				fmt.Printf("\r\033[32m[+]\033[0m Integrity check set to: %v\r\n", (cfg.Options&(1<<2)) != 0)
			} else {
				fmt.Print("\r\033[31m[!!]\033[0m Unknown setting. Use 'domain', 'resolver', 'maxlen', 'integrity', or 'debug'.\r\n")
			}
		case "send":
			var message string
			if len(args) < 2 {
				message = openVim()
				if message == "" {
					fmt.Print("\r\033[33m[-]\033[0m Empty message, nothing to send.\r\n")
					continue
				}
			} else {
				message = strings.Join(args[1:], " ")
			}
			fmt.Print("\r")
			exfil.Send(cfg, message)
		case "receive":
			if len(args) < 2 {
				fmt.Print("\rUsage: receive <message_id> [max_chars] [concurrency]\r\n")
				continue
			}
			messageID := args[1]
			maxChars := cfg.MaxLen
			concurrency := cfg.Concurrency
			if len(args) > 2 {
				if v, err := strconv.Atoi(args[2]); err == nil {
					maxChars = v
				}
			}
			if len(args) > 3 {
				if v, err := strconv.Atoi(args[3]); err == nil {
					concurrency = v
				}
			}
			exfil.Receive(cfg, messageID, maxChars, concurrency)
		default:
			fmt.Printf("\rUnknown command: %s. Type 'help' for available commands.\r\n", cmd)
		}
	}
}

func usage() {
	fmt.Print("\r\nAvailable Commands:\r\n")
	fmt.Print("  set domain <domain>      Set the target domain (e.g., web.app)\r\n")
	fmt.Print("  set resolver <ip:port>   Set the DNS resolver (e.g., 8.8.8.8:53)\r\n")
	fmt.Print("  set maxlen <number>      Set max message receive length (default 1024)\r\n")
	fmt.Print("  set debug <true|false>   Enable or disable debug output\r\n")
	fmt.Print("  show config              Display current domain and resolver settings\r\n")
	fmt.Print("  send <message>           Exfiltrate a message via DNS TTL\r\n")
	fmt.Print("  receive <message_id>     Recover a message using a specific message ID\r\n")
	fmt.Print("  exit                     Exit the dnsbin shell\r\n")
}

func openVim() string {
	tmpfile, err := ioutil.TempFile("", "dnsbin_msg_*.txt")
	if err != nil {
		fmt.Printf("\033[31m[!!]\033[0m Error creating temp file: %v\n", err)
		return ""
	}
	filename := tmpfile.Name()
	tmpfile.Close()
	defer os.Remove(filename)

	cmd := exec.Command("vim", filename)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("\033[31m[!!]\033[0m Error running vim: %v\n", err)
		return ""
	}

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("\033[31m[!!]\033[0m Error reading temp file: %v\n", err)
		return ""
	}

	return strings.TrimSpace(string(content))
}