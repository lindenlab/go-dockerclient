package manifest

import (
	"crypto/x509"

	"github.com/fsouza/go-dockerclient/external/github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient/external/github.com/docker/libtrust"
)

// Verify verifies the signature of the signed manifest returning the public
// keys used during signing.
func Verify(sm *SignedManifest) ([]libtrust.PublicKey, error) {
	js, err := libtrust.ParsePrettySignature(sm.Raw, "signatures")
	if err != nil {
		logrus.WithField("err", err).Debugf("(*SignedManifest).Verify")
		return nil, err
	}

	return js.Verify()
}

// VerifyChains verifies the signature of the signed manifest against the
// certificate pool returning the list of verified chains. Signatures without
// an x509 chain are not checked.
func VerifyChains(sm *SignedManifest, ca *x509.CertPool) ([][]*x509.Certificate, error) {
	js, err := libtrust.ParsePrettySignature(sm.Raw, "signatures")
	if err != nil {
		return nil, err
	}

	return js.VerifyChains(ca)
}
