package stellguard

import (
	"errors"

	"github.com/stellhub/stellguard-go-sdk/internal/authn"
)

var (
	ErrClientClosed           = errors.New("stellguard client is closed")
	ErrInvalidAgentCredential = authn.ErrInvalidCredential
)
