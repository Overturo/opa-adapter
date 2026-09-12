package overturo

import "testing"

func TestTokenManagerCurrent(t *testing.T) {
	tm := NewTokenManager("tat_dev_initial", "")
	if got := tm.Current(); got != "tat_dev_initial" {
		t.Errorf("Current() = %q; want %q", got, "tat_dev_initial")
	}
}

func TestTokenManagerRefreshNoEnvName(t *testing.T) {
	tm := NewTokenManager("tat_dev_initial", "")
	if tm.Refresh() != false {
		t.Errorf("Refresh() with empty envName should always return false")
	}
}

func TestTokenManagerRefreshSameValue(t *testing.T) {
	t.Setenv("OAP_TEST_TOKEN", "tat_dev_initial")
	tm := NewTokenManager("tat_dev_initial", "OAP_TEST_TOKEN")
	if tm.Refresh() != false {
		t.Errorf("Refresh() with unchanged env should return false")
	}
	if got := tm.Current(); got != "tat_dev_initial" {
		t.Errorf("Current() drifted: %q", got)
	}
}

func TestTokenManagerRefreshNewValue(t *testing.T) {
	t.Setenv("OAP_TEST_TOKEN", "tat_dev_rotated")
	tm := NewTokenManager("tat_dev_initial", "OAP_TEST_TOKEN")
	if !tm.Refresh() {
		t.Errorf("Refresh() with changed env should return true")
	}
	if got := tm.Current(); got != "tat_dev_rotated" {
		t.Errorf("Current() = %q after refresh; want tat_dev_rotated", got)
	}
}

func TestTokenManagerRefreshEmptyEnv(t *testing.T) {
	t.Setenv("OAP_TEST_TOKEN", "")
	tm := NewTokenManager("tat_dev_initial", "OAP_TEST_TOKEN")
	if tm.Refresh() != false {
		t.Errorf("Refresh() with unset env should return false (avoid wiping token)")
	}
}
