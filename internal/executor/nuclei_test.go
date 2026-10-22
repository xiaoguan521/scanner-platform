package executor

import "testing"

func TestValidateTemplateAllowsSameOriginGetPaths(t *testing.T) {
	ok := [][]byte{
		[]byte(`{"id":"baseline-root","info":{"name":"root"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]}]}`),
		[]byte(`{"id":"actuator-env","info":{"name":"actuator"},"http":[{"method":"GET","path":["{{BaseURL}}/actuator/env"],"matchers":[{"type":"word","part":"body","words":["spring"]}]}]}`),
		[]byte(`{"id":"git-config","info":{"name":"git"},"http":[{"method":"GET","path":["{{BaseURL}}/.git/config"],"matchers":[{"type":"word","part":"body","words":["[core]"]}]}]}`),
	}
	for _, data := range ok {
		if _, err := ValidateTemplate(data); err != nil {
			t.Errorf("valid read-only template rejected: %s (%v)", data, err)
		}
	}
}

func TestValidateTemplateRejectsUnsafeTemplates(t *testing.T) {
	bad := [][]byte{
		[]byte(`{"id":"post-method","info":{"name":"x"},"http":[{"method":"POST","path":["{{BaseURL}}/"],"matchers":[{"type":"status","status":[200]}]}]}`),
		[]byte(`{"id":"template-inject","info":{"name":"x"},"http":[{"method":"GET","path":["{{BaseURL}}/{{interactsh-url}}"],"matchers":[{"type":"status","status":[200]}]}]}`),
		[]byte(`{"id":"path-space","info":{"name":"x"},"http":[{"method":"GET","path":["{{BaseURL}}/a b"],"matchers":[{"type":"status","status":[200]}]}]}`),
		[]byte(`{"id":"two-requests","info":{"name":"x"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]},{"method":"GET","path":["{{BaseURL}}/b"],"matchers":[{"type":"status","status":[200]}]}]}`),
		[]byte(`{"id":"has-payloads","info":{"name":"x"},"http":[{"method":"GET","path":["{{BaseURL}}"],"payloads":{"x":["1"]},"matchers":[{"type":"status","status":[200]}]}]}`),
	}
	for _, data := range bad {
		if _, err := ValidateTemplate(data); err == nil {
			t.Errorf("unsafe template accepted: %s", data)
		}
	}
}
