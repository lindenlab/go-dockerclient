package docker

// trust.go duplicates functionality found in github.com/docker/docker/registry.
// Sadly, since this code is not in a 'pkg' for use externally, we duplicate a subset of that code here.

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fsouza/go-dockerclient/registry"

	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/digest"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/registry/client/auth"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/distribution/registry/client/transport"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/docker/pkg/ansiescape"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/docker/pkg/ioutils"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/docker/pkg/tlsconfig"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/notary/client"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/notary/pkg/passphrase"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/notary/trustmanager"
)

const (
	// OfficialNotaryServer is the endpoint serving the official Notary trust server
	OfficialNotaryServer = "https://notary.docker.io"
)

var targetRegexp = regexp.MustCompile(`([\S]+): digest: ([\S]+) size: ([\d]+)`)

func (c *Client) trustServer(index *registry.IndexInfo) string {
	if c.ContentTrustServer != "" {
		return c.ContentTrustServer
	}

	if index.Official {
		return OfficialNotaryServer
	}

	// Ping the registry to attempt trust resolution
	var (
		req            *http.Request
		resp           *http.Response
		registryServer = "https://" + index.Name
		endpointStr    = registryServer + "/v2/"
	)
	pingClient, _, _, err := c.NewHTTPSClient(index.Name, true)
	if err == nil {
		req, err = http.NewRequest("GET", endpointStr, nil)
	}
	if err == nil {
		resp, err = pingClient.Do(req)
	}
	if err == nil {
		trustServer := resp.Header.Get("X-Docker-Trust-Server")
		resp.Body.Close()
		if trustServer != "" {
			return trustServer
		}
	}

	return registryServer
}

func (c *Client) trustDirectory() string {
	return filepath.Join(c.configPath, "trust")
}

// certificateDirectory returns the directory containing
// TLS certificates for the given server. An error is
// returned if there was an error parsing the server string.
func (c *Client) certificateDirectory(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}

	return filepath.Join(c.configPath, "tls", u.Host), nil
}

type simpleCredentialStore struct {
	auth AuthConfiguration
}

func (scs simpleCredentialStore) Basic(u *url.URL) (string, string) {
	return scs.auth.Username, scs.auth.Password
}

func NewPassphraseRetrieverFromEnv() passphrase.Retriever {
	offline := os.Getenv("DOCKER_CONTENT_TRUST_OFFLINE_PASSPHRASE")
	tagging := os.Getenv("DOCKER_CONTENT_TRUST_TAGGING_PASSPHRASE")
	return NewPassphraseRetriever(offline, tagging)
}

func NewPassphraseRetriever(offline, tagging string) passphrase.Retriever {
	passphrases := map[string]string{
		"root":     offline,
		"snapshot": tagging,
		"targets":  tagging,
	}
	return func(keyName string, alias string, createNew bool, numAttempts int) (string, bool, error) {
		if v := passphrases[alias]; v != "" {
			return v, numAttempts > 1, nil
		}
		return "", false, fmt.Errorf("No passphrase provided for %s key with name %s", alias, keyName)
	}
}


func (c *Client) newTLSConfig(hostname string, serverClient bool) (*tls.Config, error) {
	// PreferredServerCipherSuites should have no effect
	var (
		certsDir  string
		tlsConfig *tls.Config
	)
	if serverClient {
		certsDir = registry.CertsDir
		tlsConfig = &tlsconfig.ServerDefault
	} else {
		certsDir = filepath.Join(c.configPath, "tls")
		tlsConfig = &tlsconfig.ClientDefault
	}

	hostDir := filepath.Join(certsDir, hostname)
	//logrus.Debugf("hostDir: %s", hostDir)
	if err := registry.ReadCertsDirectory(tlsConfig, hostDir); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

func (c *Client) NewHTTPSClient(server string, serverClient bool) (*http.Client, *http.Transport, []transport.RequestModifier, error) {
	tlsConfig, err := c.newTLSConfig(server, serverClient)
	if err != nil {
		return nil, nil, nil, err
	}
	base := registry.NewTransport(tlsConfig)
	modifiers := []transport.RequestModifier{
		transport.NewHeaderRequestModifier(http.Header{"User-Agent": []string{userAgent}}),
	}
	tr := transport.NewTransport(base, modifiers...)
	return &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}, base, modifiers, nil
}

func (c *Client) getNotaryRepository(repoInfo *registry.RepositoryInfo, authConfig AuthConfiguration, passphraseRetriever passphrase.Retriever) (*client.NotaryRepository, error) {
	server := c.trustServer(repoInfo.Index)
	if !strings.HasPrefix(server, "https://") {
		return nil, errors.New("unsupported scheme: https required for trust server")
	}

	pingClient, base, modifiers, err := c.NewHTTPSClient(server, false)
	if err != nil {
		return nil, err
	}
	endpointStr := server + "/v2/"
	req, err := http.NewRequest("GET", endpointStr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	challengeManager := auth.NewSimpleChallengeManager()
	if err := challengeManager.AddResponse(resp); err != nil {
		return nil, err
	}

	creds := simpleCredentialStore{auth: authConfig}
	tokenHandler := auth.NewTokenHandler(pingClient.Transport, creds, repoInfo.CanonicalName, "push", "pull")
	basicHandler := auth.NewBasicHandler(creds)
	modifiers = append(modifiers, transport.RequestModifier(auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler)))
	tr := transport.NewTransport(base, modifiers...)

	if passphraseRetriever == nil {
		if c.ContentTrustFromEnv {
			passphraseRetriever = NewPassphraseRetrieverFromEnv()
		} else {
			passphraseRetriever = NewPassphraseRetriever("", "")
		}
	}
	return client.NewNotaryRepository(c.trustDirectory(), repoInfo.CanonicalName, server, tr, passphraseRetriever)
}

func (c *Client) trustedTargets(repo, tag string, authConfig AuthConfiguration) ([]target, error) {
	repoInfo, err := registry.ParseRepositoryInfo(repo)
	if err != nil {
		return nil, err
	}

	notaryRepo, err := c.getNotaryRepository(repoInfo, authConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to trust repository: %s", err)
	}

	targets := []target{}
	if tag == "" {
		// List all targets
		tgts, err := notaryRepo.ListTargets()
		if err != nil {
			return nil, notaryError(err)
		}
		for _, tgt := range tgts {
			t, err := convertTarget(*tgt)
			if err != nil {
				//fmt.Fprintf(cli.out, "Skipping target for %q\n", repoInfo.LocalName)
				continue
			}
			targets = append(targets, t)
		}
	} else {
		t, err := notaryRepo.GetTargetByName(tag)
		if err != nil {
			return nil, notaryError(err)
		}
		r, err := convertTarget(*t)
		if err != nil {
			return nil, err

		}
		targets = append(targets, r)
	}

	return targets, nil
}

func (c *Client) trustedTarget(repos, tag string, authConfig AuthConfiguration) (target, error) {
	targets, err := c.trustedTargets(repos, tag, authConfig)
	if err != nil {
		return target{}, err
	}
	if len(targets) != 1 {
		return target{}, fmt.Errorf("Unexpected number of trusted targets returned: %d", len(targets))
	}
	return targets[0], nil
}

func notaryError(err error) error {
	switch err.(type) {
	case *json.SyntaxError:
		//logrus.Debugf("Notary syntax error: %s", err)
		return errors.New("no trust data available for remote repository")
	case client.ErrExpired:
		return fmt.Errorf("remote repository out-of-date: %v", err)
	case trustmanager.ErrKeyNotFound:
		return fmt.Errorf("signing keys not found: %v", err)
	}

	return err
}

type target struct {
	tag    string
	digest digest.Digest
	size   int64
}

func (t *target) ImageName(repo string) string {
	return fmt.Sprintf("%s@%s", repo, t.digest.String())
}

func convertTarget(t client.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	return target{
		tag:    t.Name,
		digest: digest.NewDigestFromHex("sha256", hex.EncodeToString(h)),
		size:   t.Length,
	}, nil
}

func (c *Client) tagTrusted(repoInfo *registry.RepositoryInfo, dgst digest.Digest, tag string) error {
	fullName := fmt.Sprintf("%s@%s", repoInfo.LocalName, dgst.String())
	//fmt.Fprintf(cli.out, "Tagging %s as %s\n", fullName, ref.ImageName(repoInfo.LocalName))
	opts := TagImageOptions{
		Repo:  repoInfo.LocalName,
		Tag:   tag,
		Force: true,
	}

	if err := c.TagImage(fullName, opts); err != nil {
		return fmt.Errorf("Error tagging trusted image: %s", err)
	}
	return nil
}

func targetStream(in io.Writer) (io.WriteCloser, <-chan []target) {
	r, w := io.Pipe()
	out := io.MultiWriter(in, w)
	targetChan := make(chan []target)

	go func() {
		targets := []target{}
		scanner := bufio.NewScanner(r)
		scanner.Split(ansiescape.ScanANSILines)
		for scanner.Scan() {
			line := scanner.Bytes()
			if matches := targetRegexp.FindSubmatch(line); len(matches) == 4 {
				dgst, err := digest.ParseDigest(string(matches[2]))
				if err != nil {
					// Line does match what is expected, continue looking for valid lines
					//logrus.Debugf("Bad digest value %q in matched line, ignoring\n", string(matches[2]))
					continue
				}
				s, err := strconv.ParseInt(string(matches[3]), 10, 64)
				if err != nil {
					// Line does match what is expected, continue looking for valid lines
					//logrus.Debugf("Bad size value %q in matched line, ignoring\n", string(matches[3]))
					continue
				}

				targets = append(targets, target{
					tag:    string(matches[1]),
					digest: dgst,
					size:   s,
				})
			}
		}
		targetChan <- targets
	}()

	return ioutils.NewWriteCloserWrapper(out, w.Close), targetChan
}

func selectKey(keys map[string]string) string {
	if len(keys) == 0 {
		return ""
	}

	keyIDs := []string{}
	for k := range keys {
		keyIDs = append(keyIDs, k)
	}

	// TODO(dmcgowan): let user choose if multiple keys, now pick consistently
	sort.Strings(keyIDs)

	return keyIDs[0]
}
