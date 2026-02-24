package telnet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/scorify/schema"
)

const (
	IAC  = 0xFF
	WILL = 0xFB
	WONT = 0xFC
	DO   = 0xFD
	DONT = 0xFE
	SB   = 0xFA
	SE   = 0xF0
)

type Schema struct {
	Server         string `key:"server"`
	Port           int    `key:"port" default:"22"`
	Username       string `key:"username"`
	Password       string `key:"password"`
	Command        string `key:"command"`
	ExpectedOutput string `key:"expected_output"`
}

func Validate(config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.Server == "" {
		return fmt.Errorf("server is required; got %q", conf.Server)
	}

	if conf.Port <= 0 || conf.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535; got %d", conf.Port)
	}

	if conf.Username == "" {
		return fmt.Errorf("username is required; got %q", conf.Username)
	}

	if conf.Password == "" {
		return fmt.Errorf("password is required; got %q", conf.Password)
	}

	if conf.Command == "" {
		return fmt.Errorf("command is required; got %q", conf.Command)
	}

	return nil
}

// handleIAC reads the rest of an IAC sequence and sends the
// appropriate refusal response. Returns true if an IAC was handled.
func handleIAC(conn net.Conn, firstByte byte) bool {
	if firstByte != IAC {
		return false
	}

	cmd := make([]byte, 1)
	if _, err := conn.Read(cmd); err != nil {
		return true
	}

	switch cmd[0] {
	case DO:
		// Server asks us to DO something — refuse with WONT
		opt := make([]byte, 1)
		conn.Read(opt)
		conn.Write([]byte{IAC, WONT, opt[0]})

	case WILL:
		// Server says it WILL do something — refuse with DONT
		opt := make([]byte, 1)
		conn.Read(opt)
		conn.Write([]byte{IAC, DONT, opt[0]})

	case WONT, DONT:
		// Server refusing something, just consume the option byte
		opt := make([]byte, 1)
		conn.Read(opt)

	case SB:
		// Subnegotiation — read until IAC SE
		one := make([]byte, 1)
		for {
			if _, err := conn.Read(one); err != nil {
				return true
			}
			if one[0] == IAC {
				if _, err := conn.Read(one); err != nil {
					return true
				}
				if one[0] == SE {
					break
				}
			}
		}

	default:
		// Some other 2-byte IAC command, just consume it
	}

	return true
}

func readUntilAny(
	conn net.Conn,
	targets []string,
) (string, error) {

	var buf bytes.Buffer
	one := make([]byte, 1)

	for {
		n, err := conn.Read(one)
		if n > 0 {
			if handleIAC(conn, one[0]) {
				continue
			}

			buf.Write(one[:n])
			s := buf.String()

			for _, t := range targets {
				if strings.Contains(s, t) {
					return s, nil
				}
			}
		}

		if err != nil {
			return buf.String(), fmt.Errorf("read error waiting for %v: %w", targets, err)
		}
	}
}

// sendLine writes a string followed by a telnet newline (\r\n).
func sendLine(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

func Run(ctx context.Context, config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("context deadline is not set")
	}

	connStr := fmt.Sprintf("%s:%d", conf.Server, conf.Port)

	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", connStr)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", connStr, err)
	}
	defer conn.Close()

	conn.SetDeadline(deadline)

	// 1. Wait for login prompt
	_, err = readUntilAny(conn, []string{"ogin:"})
	if err != nil {
		return fmt.Errorf("failed waiting for login prompt: %v", err)
	}

	if err := sendLine(conn, conf.Username); err != nil {
		return fmt.Errorf("failed sending username: %v", err)
	}

	// 2. Wait for password prompt
	_, err = readUntilAny(conn, []string{"assword:"})
	if err != nil {
		return fmt.Errorf("failed waiting for password prompt: %v", err)
	}

	if err := sendLine(conn, conf.Username); err != nil {
		return fmt.Errorf("failed sending password: %v", err)
	}

	// 3. Wait for shell prompt (more robust detection)
	_, err = readUntilAny(conn, []string{"$ ", "# "})
	if err != nil {
		return fmt.Errorf("failed waiting for shell prompt: %v", err)
	}

	// 4. Send command
	if err := sendLine(conn, conf.Command); err != nil {
		return fmt.Errorf("failed sending command: %v", err)
	}

	// 5. Read until prompt returns again
	cmdOutput, err := readUntilAny(conn, []string{"$ ", "# "})
	if err != nil {
		return fmt.Errorf("failed reading command output: %v", err)
	}

	expected := []byte(conf.ExpectedOutput)
	if !bytes.Contains([]byte(cmdOutput), expected) {
		return fmt.Errorf("failed: outputs do not match; got: %s", cmdOutput)
	}
	return nil
}
