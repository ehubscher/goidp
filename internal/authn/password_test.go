package authn_test

import (
	"testing"

	"github.com/ehubscher/goidp/internal/authn"
)

var passwords = []struct {
	in  []string
	out bool
}{
	{[]string{"password123", "$argon2id$v=19,m=65536,t=6,p=2$gQc4ZccIqosKqCMKYUgP8A$x/xg/7uiPsBrRd11wC0mtiM2fjeqHzqTcjs2fLMsiGw"}, true},
	{[]string{"password123", "$bcrypt$c=4$JDJhJDA0JDVWaEhScW5XTUtESmN6U3NyL3FMZHV5UnBsamsxV08wTjNINXNmdVdFd0tmdU5MZ1I4ck02"}, true},
}

func TestVerifyPassword(t *testing.T) {
	for _, password := range passwords {
		match, err := authn.VerifyPassword(password.in[0], password.in[1])
		if err != nil {
			t.Errorf("got: %v, want: %v", match, password.out)
		}
	}
}
