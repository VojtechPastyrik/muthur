package auth

import (
	"crypto/x509"
	"fmt"
	"time"
)

// TrustPools is the vendor PKI as the brain sees it: the root (or roots) it
// anchors on and the intermediate that signs collector leaves. The mTLS
// listener folds both into one ClientCAs pool; the signed transport needs
// them apart so x509.Verify can build a proper chain.
type TrustPools struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

// LoadTrustPools reads the trust root bundle and, when set, the intermediate
// CA certificate.
func LoadTrustPools(trustRootFile, intermediateCAFile string) (*TrustPools, error) {
	roots, err := loadCertPool(trustRootFile)
	if err != nil {
		return nil, fmt.Errorf("load trust root: %w", err)
	}
	inter := x509.NewCertPool()
	if intermediateCAFile != "" {
		if err := appendCertsFromFile(inter, intermediateCAFile); err != nil {
			return nil, fmt.Errorf("load intermediate CA: %w", err)
		}
	}
	return &TrustPools{Roots: roots, Intermediates: inter}, nil
}

// VerifyClientLeaf checks that leaf chains to the vendor PKI and is valid for
// client authentication at now.
func (t *TrustPools) VerifyClientLeaf(leaf *x509.Certificate, now time.Time) error {
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         t.Roots,
		Intermediates: t.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}
