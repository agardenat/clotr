//go:build !unix

package integrity

import "errors"

const TrustFile = ""

func rootOwned(string) error {
	return errors.ErrUnsupported
}
