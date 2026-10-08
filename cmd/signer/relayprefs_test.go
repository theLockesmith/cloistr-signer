package main

import (
	"strings"
	"testing"
)

func TestNewRelayPrefsClient_RequiresVariables(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "fallback unset",
			env:     map[string]string{"USE_CLOISTR_FALLBACK": ""},
			wantErr: "USE_CLOISTR_FALLBACK",
		},
		{
			name:    "fallback on without discovery",
			env:     map[string]string{"USE_CLOISTR_FALLBACK": "true", "RELAYPREFS_CLOISTR_DISCOVERY": "", "RELAYPREFS_CLOISTR_RELAY": "wss://relay.example"},
			wantErr: "RELAYPREFS_CLOISTR_DISCOVERY",
		},
		{
			name:    "fallback on without relay",
			env:     map[string]string{"USE_CLOISTR_FALLBACK": "true", "RELAYPREFS_CLOISTR_DISCOVERY": "https://discover.example", "RELAYPREFS_CLOISTR_RELAY": ""},
			wantErr: "RELAYPREFS_CLOISTR_RELAY",
		},
		{
			name: "all set",
			env:  map[string]string{"USE_CLOISTR_FALLBACK": "true", "RELAYPREFS_CLOISTR_DISCOVERY": "https://discover.example", "RELAYPREFS_CLOISTR_RELAY": "wss://relay.example"},
		},
		{
			name: "fallback off",
			env:  map[string]string{"USE_CLOISTR_FALLBACK": "false", "RELAYPREFS_CLOISTR_DISCOVERY": "", "RELAYPREFS_CLOISTR_RELAY": ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			client, err := newRelayPrefsClient()
			if tt.wantErr == "" {
				if err != nil || client == nil {
					t.Fatalf("expected a client, got err %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected an error naming %s, got %v", tt.wantErr, err)
			}
		})
	}
}
