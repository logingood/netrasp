package netrasp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is an in-process SSH server that counts how many client
// transports are still open, so tests can assert that netrasp never leaves
// a connection (and therefore a device vty) behind.
type testSSHServer struct {
	t        *testing.T
	listener net.Listener
	config   *ssh.ServerConfig
	prompt   string // written after the shell starts; empty = never send a prompt
	noSSH    bool   // accept TCP but never speak SSH

	mu   sync.Mutex
	open int
	seen int
}

func newTestSSHServer(t *testing.T, prompt string, noSSH bool) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{t: t, listener: l, config: cfg, prompt: prompt, noSSH: noSSH}
	t.Cleanup(func() { l.Close() })

	go s.serve()

	return s
}

func (s *testSSHServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *testSSHServer) serve() {
	for {
		nConn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.open++
		s.seen++
		s.mu.Unlock()
		go s.handle(nConn)
	}
}

func (s *testSSHServer) handle(nConn net.Conn) {
	defer func() {
		nConn.Close()
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()

	if s.noSSH {
		// Hold the socket until the client gives up and closes it.
		buf := make([]byte, 1)
		for {
			if _, err := nConn.Read(buf); err != nil {
				return
			}
		}
	}

	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for newCh := range chans {
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range chReqs {
					req.Reply(true, nil)
					if req.Type == "shell" && s.prompt != "" {
						ch.Write([]byte(s.prompt))
					}
				}
			}()
			go func() {
				// Echo a prompt for every command so Run() completes.
				buf := make([]byte, 1024)
				for {
					if _, err := ch.Read(buf); err != nil {
						return
					}
					if s.prompt != "" {
						ch.Write([]byte("\r\n" + s.prompt))
					}
				}
			}()
		}
	}()
	// Wait returns only once the client transport is gone. A session
	// close alone is not enough — that's the leak this file guards.
	conn.Wait()
}

func (s *testSSHServer) openConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.open
}

func (s *testSSHServer) seenConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.seen
}

func (s *testSSHServer) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.openConns() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected all client connections to be closed, %d still open", s.openConns())
}

func newTestDevice(t *testing.T, s *testSSHServer, opts ...ConfigOpt) Platform {
	t.Helper()
	opts = append([]ConfigOpt{
		WithUsernamePassword("user", "pass"),
		WithSSHPort(s.port()),
		WithInsecureIgnoreHostKey(),
		WithDriver("ios"),
	}, opts...)
	device, err := New("127.0.0.1", opts...)
	if err != nil {
		t.Fatal(err)
	}

	return device
}

func TestSSHCloseClosesTransport(t *testing.T) {
	s := newTestSSHServer(t, "switch1#", false)
	device := newTestDevice(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := device.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := device.Run(ctx, "show version"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := device.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	s.waitClosed(t)
}

func TestSSHCloseIsIdempotent(t *testing.T) {
	s := newTestSSHServer(t, "switch1#", false)
	device := newTestDevice(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := device.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	device.Close(context.Background())
	device.Close(context.Background())

	s.waitClosed(t)
}

func TestSSHCloseWithoutDialDoesNotPanic(t *testing.T) {
	s := newTestSSHServer(t, "switch1#", false)
	device := newTestDevice(t, s)

	if err := device.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The device never shows a prompt, so Dial fails waiting for it. Callers
// only defer Close after a successful Dial, so Dial itself must tear the
// connection down or the vty stays occupied.
func TestSSHDialFailureAfterShellClosesTransport(t *testing.T) {
	s := newTestSSHServer(t, "", false)
	device := newTestDevice(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := device.Dial(ctx); err == nil {
		t.Fatal("expected dial to fail without a prompt")
	}
	if s.seenConns() != 1 {
		t.Fatalf("expected 1 connection attempt, got %d", s.seenConns())
	}

	s.waitClosed(t)
}

// A peer that accepts TCP but never completes the SSH handshake must not
// hang Dial beyond the caller's context.
func TestSSHDialHonoursContextDuringHandshake(t *testing.T) {
	s := newTestSSHServer(t, "switch1#", true)
	device := newTestDevice(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := device.Dial(ctx); err == nil {
		t.Fatal("expected dial to fail against a silent peer")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("dial ignored context deadline, took %s", elapsed)
	}

	s.waitClosed(t)
}
