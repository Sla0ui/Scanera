package models

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if config.MaxConcurrentChecks != 5 {
		t.Errorf("Expected MaxConcurrentChecks=5, got %d", config.MaxConcurrentChecks)
	}

	if !config.VerifyTLS {
		t.Error("Expected VerifyTLS=true by default for security")
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("Expected Timeout=10s, got %v", config.Timeout)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid concurrency (too low)",
			config: &Config{
				MaxConcurrentChecks: 0,
				Timeout:             10 * time.Second,
				OutputDir:           "results",
				SuccessStatusCodes:  []int{200},
			},
			wantErr: true,
		},
		{
			name: "invalid concurrency (too high)",
			config: &Config{
				MaxConcurrentChecks: 101,
				Timeout:             10 * time.Second,
				OutputDir:           "results",
				SuccessStatusCodes:  []int{200},
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			config: &Config{
				MaxConcurrentChecks: 5,
				Timeout:             500 * time.Millisecond,
				OutputDir:           "results",
				SuccessStatusCodes:  []int{200},
			},
			wantErr: true,
		},
		{
			name: "empty output directory",
			config: &Config{
				MaxConcurrentChecks: 5,
				Timeout:             10 * time.Second,
				OutputDir:           "",
				SuccessStatusCodes:  []int{200},
			},
			wantErr: true,
		},
		{
			name: "no success status codes",
			config: &Config{
				MaxConcurrentChecks: 5,
				Timeout:             10 * time.Second,
				OutputDir:           "results",
				SuccessStatusCodes:  []int{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.SuccessStatusCodes = []int{200, 301, 302}

	clone := original.Clone()

	// Modify clone
	clone.SuccessStatusCodes[0] = 999
	clone.MaxConcurrentChecks = 100

	// Original should be unchanged
	if original.SuccessStatusCodes[0] != 200 {
		t.Errorf("Clone modified original SuccessStatusCodes")
	}
	if original.MaxConcurrentChecks != 5 {
		t.Errorf("Clone modified original MaxConcurrentChecks")
	}
}
