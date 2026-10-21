package inventory

import "testing"

func TestValidateRuntimeServices(t *testing.T) {
	valid := RuntimeService{Name: "apache2", Manager: "systemd", State: "installed"}
	for _, tc := range []struct {
		name     string
		services []RuntimeService
		want     bool
	}{
		{name: "empty", services: nil, want: true},
		{name: "valid", services: []RuntimeService{valid, {Name: "sshd", Manager: "process", State: "running"}}, want: true},
		{name: "duplicate", services: []RuntimeService{valid, valid}, want: false},
		{name: "invalid manager", services: []RuntimeService{{Name: "apache2", Manager: "launchd", State: "running"}}, want: false},
		{name: "invalid state", services: []RuntimeService{{Name: "apache2", Manager: "systemd", State: "failed"}}, want: false},
		{name: "unsafe name", services: []RuntimeService{{Name: "apache 2", Manager: "systemd", State: "installed"}}, want: false},
		{name: "empty name", services: []RuntimeService{{Manager: "systemd", State: "installed"}}, want: false},
		{name: "long name", services: []RuntimeService{{Name: string(make([]byte, 129)), Manager: "systemd", State: "installed"}}, want: false},
		{name: "too many", services: makeRuntimeServices(257), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidateRuntimeServices(tc.services); got != tc.want {
				t.Fatalf("ValidateRuntimeServices()=%t, want %t", got, tc.want)
			}
		})
	}
}

func FuzzValidateRuntimeServices(f *testing.F) {
	f.Add("systemd", "apache2", "installed")
	f.Add("process", "sshd", "running")
	f.Fuzz(func(t *testing.T, manager, name, state string) {
		_ = ValidateRuntimeServices([]RuntimeService{{Manager: manager, Name: name, State: state}})
	})
}

func makeRuntimeServices(count int) []RuntimeService {
	services := make([]RuntimeService, count)
	for i := range services {
		services[i] = RuntimeService{Name: "service" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Manager: "systemd", State: "installed"}
	}
	return services
}
