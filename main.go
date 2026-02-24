package ssh

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/scorify/schema"
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

	address := net.JoinHostPort(conf.Server, strconv.Itoa(conf.Port))
	conn, err := net.DialTimeout("tcp", address, time.Until(deadline))
	if err != nil {
		return fmt.Errorf("tcp dial failed")
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("context deadline is not set")
		}
		if strings.Contains(line, "login:") {
			fmt.Fprintf(conn, "%s\n", conf.Username)
			break
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("context deadline is not set")
		}
		if strings.Contains(line, "Password:") {
			fmt.Fprintf(conn, "%s\n", conf.Password)
			break
		}
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("context deadline is not set")
	}
	if strings.Contains(line, "login:") {
		return fmt.Errorf("Login failed")
	}

	time.Sleep(.5 * time.Second)

	fmt.Fprintf(conn, "%s\n", conf.Command)

	var result strings.Builder
	for {
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		result.WriteString(line)
	}

	outputString := strings.TrimSpace(string(result.String()))
	expectedOutputString := strings.TrimSpace(conf.ExpectedOutput)

	if outputString != expectedOutputString {
		return fmt.Errorf("expected output \"%s\" but got \"%s\"", expectedOutputString, outputString)
	}
	return nil
}
