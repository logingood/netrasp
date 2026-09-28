package netrasp

import (
	"context"
	"fmt"
	"regexp"
)

// establishConnection dials the device and prepares the session. If anything
// after the transport is up fails (no prompt, preparation command error,
// ctx timeout) the connection is closed before returning, because callers
// only defer Close after a successful Dial.
func establishConnection(ctx context.Context, p Platform, c connection, prompt *regexp.Regexp, preparationCommands []string) (err error) {
	err = c.Dial(ctx)
	if err != nil {
		return fmt.Errorf("unable to open connection: %w", err)
	}
	defer func() {
		if err != nil {
			c.Close(context.Background())
		}
	}()

	reader := c.Recv(ctx)
	// Make sure that we find the initial prompt to clear the buffer before we continue
	_, err = readUntilPrompt(ctx, reader, prompt)
	if err != nil {
		return fmt.Errorf("unable to find the initial prompt: %w", err)
	}

	for _, command := range preparationCommands {
		output, err := p.Run(ctx, command)
		if err != nil {
			return fmt.Errorf("unable to prepare session using the command '%s': %w", output, err)
		}
	}

	return nil
}
