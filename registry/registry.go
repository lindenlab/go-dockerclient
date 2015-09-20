// Copyright 2015 go-dockerclient authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package registry

// registry.go duplicates functionality found in github.com/docker/docker/registry.
// Sadly, since this code is not in a 'pkg' for use externally, we duplicate a subset of that code here.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/digest"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/registry/api/v2"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/docker/pkg/tlsconfig"
)

const (
	// OfficialIndexName is the name of the official index
	OfficialIndexName = "docker.io"

	// CertsDir is the directory where certificates are stored
	CertsDir = "/etc/docker/certs.d"
)

var (
	// ErrInvalidRepositoryName is an error returned if the repository name did
	// not have the correct form
	ErrInvalidRepositoryName = errors.New("Invalid repository name (ex: \"registry.domain.tld/myrepos\")")

	validImageHex = regexp.MustCompile(`^([a-f0-9]{64})$`)
)

type IndexInfo struct {
	// Name is the name of the registry, such as "docker.io"
	Name string
	// Official indicates whether this is an official registry
	Official bool
}

// RepositoryInfo describes a repository
type RepositoryInfo struct {
	// Index points to registry information
	Index *IndexInfo
	// RemoteName is the remote name of the repository, such as
	// "library/ubuntu-12.04-base"
	RemoteName string
	// LocalName is the local name of the repository, such as
	// "ubuntu-12.04-base"
	LocalName string
	// CanonicalName is the canonical name of the repository, such as
	// "docker.io/library/ubuntu-12.04-base"
	CanonicalName string
	// Official indicates whether the repository is considered official.
	// If the registry is official, and the normalized name does not
	// contain a '/' (e.g. "foo"), then it is considered an official repo.
	Official bool
}

// splitReposName breaks a reposName into an index name and remote name
func splitReposName(reposName string) (string, string) {
	nameParts := strings.SplitN(reposName, "/", 2)
	var indexName, remoteName string
	if len(nameParts) == 1 || (!strings.Contains(nameParts[0], ".") &&
		!strings.Contains(nameParts[0], ":") && nameParts[0] != "localhost") {
		// This is a Docker Index repos (ex: samalba/hipache or ubuntu)
		// 'docker.io'
		indexName = OfficialIndexName
		remoteName = reposName
	} else {
		indexName = nameParts[0]
		remoteName = nameParts[1]
	}
	return indexName, remoteName
}

func validateRemoteName(remoteName string) error {
	if !strings.Contains(remoteName, "/") {
		// the repository name must not be a valid image ID
		if ok := validImageHex.MatchString(remoteName); ok {
			return fmt.Errorf("Invalid repository name (%s), cannot specify 64-byte hexadecimal strings", remoteName)
		}
	}

	return v2.ValidateRepositoryName(remoteName)
}

// ParseRepositoryInfo validates and breaks down a repository name into a RepositoryInfo
func ParseRepositoryInfo(reposName string) (*RepositoryInfo, error) {
	if strings.Contains(reposName, "://") {
		return nil, ErrInvalidRepositoryName
	}

	indexName, remoteName := splitReposName(reposName)
	if err := validateRemoteName(remoteName); err != nil {
		return nil, err
	}

	repoInfo := &RepositoryInfo{
		RemoteName: remoteName,
		Index: &IndexInfo{
			Name:     indexName,
			Official: (indexName == OfficialIndexName),
		},
	}

	if repoInfo.Index.Official {
		normalizedName := repoInfo.RemoteName
		if strings.HasPrefix(normalizedName, "library/") {
			// If pull "library/foo", it's stored locally under "foo"
			normalizedName = strings.SplitN(normalizedName, "/", 2)[1]
		}

		repoInfo.LocalName = normalizedName
		repoInfo.RemoteName = normalizedName
		// If the normalized name does not contain a '/' (e.g. "foo")
		// then it is an official repo.
		if strings.IndexRune(normalizedName, '/') == -1 {
			repoInfo.Official = true
			// Fix up remote name for official repos.
			repoInfo.RemoteName = "library/" + normalizedName
		}

		repoInfo.CanonicalName = "docker.io/" + repoInfo.RemoteName
	} else {
		repoInfo.LocalName = repoInfo.Index.Name + "/" + repoInfo.RemoteName
		repoInfo.CanonicalName = repoInfo.LocalName

	}

	return repoInfo, nil
}

func hasFile(files []os.FileInfo, name string) bool {
	for _, f := range files {
		if f.Name() == name {
			return true
		}
	}
	return false
}

// ReadCertsDirectory reads the directory for TLS certificates
// including roots and certificate pairs and updates the
// provided TLS configuration.
func ReadCertsDirectory(tlsConfig *tls.Config, directory string) error {
	fs, err := ioutil.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, f := range fs {
		if strings.HasSuffix(f.Name(), ".crt") {
			if tlsConfig.RootCAs == nil {
				// TODO(dmcgowan): Copy system pool
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			//logrus.Debugf("crt: %s", filepath.Join(directory, f.Name()))
			data, err := ioutil.ReadFile(filepath.Join(directory, f.Name()))
			if err != nil {
				return err
			}
			tlsConfig.RootCAs.AppendCertsFromPEM(data)
		}
		if strings.HasSuffix(f.Name(), ".cert") {
			certName := f.Name()
			keyName := certName[:len(certName)-5] + ".key"
			//logrus.Debugf("cert: %s", filepath.Join(directory, f.Name()))
			if !hasFile(fs, keyName) {
				return fmt.Errorf("Missing key %s for certificate %s", keyName, certName)
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(directory, certName), filepath.Join(directory, keyName))
			if err != nil {
				return err
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
		if strings.HasSuffix(f.Name(), ".key") {
			keyName := f.Name()
			certName := keyName[:len(keyName)-4] + ".cert"
			//logrus.Debugf("key: %s", filepath.Join(directory, f.Name()))
			if !hasFile(fs, certName) {
				return fmt.Errorf("Missing certificate %s for key %s", certName, keyName)
			}
		}
	}

	return nil
}

// ParseDigest attempts to parse a string into a digest. Returns nil otherwise.
func ParseDigest(s string) *digest.Digest {
	if strings.Contains(s, ":") {
		dgst, err := digest.ParseDigest(s)
		if err == nil {
			return &dgst
		}
	}
	return nil
}

func IsDigest(tag string) bool {
	digest := ParseDigest(tag)
	return digest != nil
}

// NewTransport returns a new HTTP transport. If tlsConfig is nil, it uses the
// default TLS configuration.
func NewTransport(tlsConfig *tls.Config) *http.Transport {
	if tlsConfig == nil {
		var cfg = tlsconfig.ServerDefault
		tlsConfig = &cfg
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		// TODO(dmcgowan): Call close idle connections when complete and use keep alive
		DisableKeepAlives: true,
	}
}
