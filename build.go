// Copyright 2015 go-dockerclient authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docker

import (
	"errors"
	"fmt"
	"io"
)

var (
	// ErrMissingOutputStream is the error returned when no output stream
	// is provided to some calls, like BuildImage.
	ErrMissingOutputStream = errors.New("missing output stream")

	// ErrMultipleContexts is the error returned when both a ContextDir and
	// InputStream are provided in BuildImageOptions
	ErrMultipleContexts = errors.New("image build may not be provided BOTH context dir and input stream")
)

// BuildImageOptions present the set of informations available for building an
// image from a tarfile with a Dockerfile in it.
//
// For more details about the Docker building process, see
// http://goo.gl/tlPXPu.
type BuildImageOptions struct {
	Name                string             `qs:"t"`
	Dockerfile          string             `qs:"dockerfile"`
	NoCache             bool               `qs:"nocache"`
	SuppressOutput      bool               `qs:"q"`
	Pull                bool               `qs:"pull"`
	RmTmpContainer      bool               `qs:"rm"`
	ForceRmTmpContainer bool               `qs:"forcerm"`
	Memory              int64              `qs:"memory"`
	Memswap             int64              `qs:"memswap"`
	CPUShares           int64              `qs:"cpushares"`
	CPUSetCPUs          string             `qs:"cpusetcpus"`
	InputStream         io.Reader          `qs:"-"`
	OutputStream        io.Writer          `qs:"-"`
	RawJSONStream       bool               `qs:"-"`
	Remote              string             `qs:"remote"`
	Auth                AuthConfiguration  `qs:"-"` // for older docker X-Registry-Auth header
	AuthConfigs         AuthConfigurations `qs:"-"` // for newer docker X-Registry-Config header
	ContextDir          string             `qs:"-"`
}

// BuildImage builds an image from a tarball's url or a Dockerfile in the input
// stream.
//
// See https://goo.gl/xySxCe for more details.
func (c *Client) BuildImage(opts BuildImageOptions) error {
	if opts.OutputStream == nil {
		return ErrMissingOutputStream
	}
	headers, err := headersWithAuth(opts.Auth, c.versionedAuthConfigs(opts.AuthConfigs))
	if err != nil {
		return err
	}

	if opts.Remote != "" && opts.Name == "" {
		opts.Name = opts.Remote
	}
	if opts.InputStream != nil || opts.ContextDir != "" {
		headers["Content-Type"] = "application/tar"
	} else if opts.Remote == "" {
		return ErrMissingRepo
	}
	if opts.ContextDir != "" {
		if opts.InputStream != nil {
			return ErrMultipleContexts
		}
		var err error
		if opts.InputStream, err = createTarStream(opts.ContextDir, opts.Dockerfile); err != nil {
			return err
		}
	}

	return c.stream("POST", fmt.Sprintf("/build?%s", queryString(&opts)), streamOptions{
		setRawTerminal: true,
		rawJSONStream:  opts.RawJSONStream,
		headers:        headers,
		in:             opts.InputStream,
		stdout:         opts.OutputStream,
	})
}


