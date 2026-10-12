package seal

import "fmt"

// FromConfig builds the sealer for SESSION_SEALER. t may be nil unless mode is
// vault. A keyfile that does not exist yet is created (0600).
func FromConfig(mode, keyfile, vaultKey string, t Transit) (Sealer, error) {
	switch mode {
	case ModeNone:
		return None{}, nil
	case ModeKeyfile:
		return LoadKeyfile(keyfile, true)
	case ModeVault:
		return NewVault(t, vaultKey)
	}
	return nil, fmt.Errorf("seal: unknown SESSION_SEALER %q", mode)
}
