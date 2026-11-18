package nvme

import (
	"context"
	"fmt"
)

// Transport carries one admin command to a controller. data is the command's data
// buffer (DataLen bytes; nil for none). It returns the completion's command-specific
// result (DW0) and status; err means the command could not be delivered.
type Transport interface {
	AdminCommand(ctx context.Context, c AdminCmd, data []byte) (result uint32, status Status, err error)
}

// Device sends admin commands over a Transport.
type Device struct{ T Transport }

// Exec runs one command; a non-zero status is a *CommandError.
func (d Device) Exec(ctx context.Context, c Command, data []byte) (uint32, error) {
	if len(data) != int(c.Cmd.DataLen) {
		return 0, fmt.Errorf("%s: data buffer %d bytes, command transfers %d", c.Name, len(data), c.Cmd.DataLen)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	res, st, err := d.T.AdminCommand(ctx, c.Cmd, data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", c.Name, err)
	}
	if st.Code() != 0 {
		return res, &CommandError{Cmd: c.Name, Status: st}
	}
	return res, nil
}

// Controller reads Identify Controller; raw is returned for recording.
func (d Device) Controller(ctx context.Context) (*Controller, []byte, error) {
	b := make([]byte, IdentifyBytes)
	if _, err := d.Exec(ctx, IdentifyController(), b); err != nil {
		return nil, nil, err
	}
	c, err := ParseController(b)
	return c, b, err
}

// Namespace reads Identify Namespace nsid.
func (d Device) Namespace(ctx context.Context, nsid uint32) (*Namespace, []byte, error) {
	b := make([]byte, IdentifyBytes)
	if _, err := d.Exec(ctx, IdentifyNamespace(nsid), b); err != nil {
		return nil, nil, err
	}
	n, err := ParseNamespace(nsid, b)
	return n, b, err
}

// ActiveNamespaces lists the active namespace IDs.
func (d Device) ActiveNamespaces(ctx context.Context) ([]uint32, error) {
	b := make([]byte, IdentifyBytes)
	if _, err := d.Exec(ctx, IdentifyActiveNamespaces(), b); err != nil {
		return nil, err
	}
	return ParseNamespaceList(b)
}

// SanitizeStatus reads the Sanitize Status log page.
func (d Device) SanitizeStatus(ctx context.Context) (SanitizeLog, error) {
	b := make([]byte, SanitizeLogBytes)
	if _, err := d.Exec(ctx, SanitizeStatusLog(), b); err != nil {
		return SanitizeLog{}, err
	}
	return ParseSanitizeLog(b)
}
