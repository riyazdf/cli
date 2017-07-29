package formatter

import (
	"sort"
	"strings"
)

const (
	defaultTrustTagTableFormat = "table {{.SignedTag}}\t{{.Digest}}\t{{.Signers}}"
	signedTagNameHeader        = "SIGNED TAG"
	trustedDigestHeader        = "DIGEST"
	signersHeader              = "SIGNERS"
)

// SignedTagInfo represents all formatted information needed to describe a signed tag:
// Name: name of the signed tag
// Digest: hex encoded digest of the contents
// Signers: list of entities who signed the tag
type SignedTagInfo struct {
	Name    string
	Digest  string
	Signers []string
}

// NewTrustTagFormat returns a Format for rendering using a trusted tag Context
func NewTrustTagFormat() Format {
	return defaultTrustTagTableFormat
}

// TrustTagWrite writes the context
func TrustTagWrite(ctx Context, signedTagInfoList []SignedTagInfo) error {
	render := func(format func(subContext subContext) error) error {
		for _, signedTag := range signedTagInfoList {
			if err := format(&trustTagContext{s: signedTag}); err != nil {
				return err
			}
		}
		return nil
	}
	trustTagCtx := trustTagContext{}
	trustTagCtx.header = trustTagHeaderContext{
		"SignedTag": signedTagNameHeader,
		"Digest":    trustedDigestHeader,
		"Signers":   signersHeader,
	}
	return ctx.Write(&trustTagCtx, render)
}

type trustTagHeaderContext map[string]string

type trustTagContext struct {
	HeaderContext
	s SignedTagInfo
}

// SignedTag returns the name of the signed tag
func (c *trustTagContext) SignedTag() string {
	return c.s.Name
}

// Digest returns the hex encoded digest associated with this signed tag
func (c *trustTagContext) Digest() string {
	return c.s.Digest
}

// Signers returns the sorted list of entities who signed this tag
func (c *trustTagContext) Signers() string {
	sort.Strings(c.s.Signers)
	return strings.Join(c.s.Signers, ",")
}
