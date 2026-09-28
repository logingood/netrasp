package netrasp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshConnection contains configuration and connection information for SSH.
type sshConnection struct {
	Config  *ssh.ClientConfig
	Host    *host
	reader  io.Reader
	writer  io.Writer
	client  *ssh.Client
	session *ssh.Session
}

// Dial opens an SSH connection.
//
// The TCP connect and SSH handshake honour both ctx and Config.Timeout. On
// any failure the partially opened transport is closed, so a failed Dial
// never leaves a session (and a device vty) behind.
func (s *sshConnection) Dial(ctx context.Context) (err error) {
	addr := net.JoinHostPort(s.Host.Address, strconv.Itoa(s.Host.Port))
	dialer := net.Dialer{Timeout: s.Config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("unable to establish connection: %w", err)
	}

	// ssh.NewClientConn has no context support; bound the handshake with a
	// deadline and abort it outright if ctx is cancelled first.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-handshakeDone:
		}
	}()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, s.Config)
	close(handshakeDone)
	if err != nil {
		conn.Close()

		return fmt.Errorf("unable to establish connection: %w", err)
	}
	conn.SetDeadline(time.Time{})

	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() {
		if err != nil {
			client.Close()
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("unable to open new session: %w", err)
	}

	terminalMode := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 28800,
		ssh.TTY_OP_OSPEED: 28800,
	}
	err = session.RequestPty("xterm", 80, 40, terminalMode)
	if err != nil {
		return fmt.Errorf("error requesting pty terminal: %w", err)
	}

	s.reader, err = session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error requesting StdoutPipe: %w", err)
	}
	s.writer, err = session.StdinPipe()
	if err != nil {
		return fmt.Errorf("error requesting StdinPipe: %w", err)
	}

	err = session.Shell()
	if err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	s.client = client
	s.session = session

	return nil
}

// GetHost returns information about the connected host.
func (s *sshConnection) GetHost() *host {
	return s.Host
}

// Close disconnects from the device.
//
// Closing only the session channel is not enough: the SSH transport stays
// up and many devices keep the vty allocated until their exec-timeout. Close
// tears down the whole client and is safe to call more than once or without
// a successful Dial.
func (s *sshConnection) Close(ctx context.Context) error {
	if s.session != nil {
		s.session.Close()
		s.session = nil
	}
	if s.client != nil {
		err := s.client.Close()
		s.client = nil

		return err
	}

	return nil
}

// Send is used to write commands to the device.
func (s *sshConnection) Send(ctx context.Context, command string) error {
	_, err := s.writer.Write([]byte(command + "\n"))
	if err != nil {
		return fmt.Errorf("unable to send command to device: %w", err)
	}

	return nil
}

// Recv is used to read data from the device.
func (s *sshConnection) Recv(ctx context.Context) io.Reader {
	return newContextReader(ctx, s.reader)
}
