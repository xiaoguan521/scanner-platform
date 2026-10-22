import unittest

from curate_nuclei_templates import convert, normalize_id


def tmpl(**over):
    base = {
        "id": "CVE-2021-TEST",
        "info": {"name": "Example exposure", "severity": "high", "tags": "cve,exposure"},
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/actuator/env"],
            "matchers": [{"type": "word", "part": "body", "words": ["activeProfiles"]}],
        }],
    }
    base.update(over)
    return base


class CurateTest(unittest.TestCase):
    def test_keeps_read_only_get_path_template(self):
        out = convert(tmpl())
        self.assertIsNotNone(out)
        self.assertEqual(out["id"], "cve-2021-test")
        http = out["http"][0]
        self.assertEqual(http["method"], "GET")
        self.assertEqual(http["path"], ["{{BaseURL}}/actuator/env"])

    def test_keeps_status_matcher(self):
        out = convert(tmpl(http=[{"method": "GET", "path": ["{{BaseURL}}/admin"],
                                  "matchers": [{"type": "status", "status": [200]}]}]))
        self.assertIsNotNone(out)

    def test_drops_non_get(self):
        self.assertIsNone(convert(tmpl(http=[{"method": "POST", "path": ["{{BaseURL}}/"],
                                              "matchers": [{"type": "status", "status": [200]}]}])))

    def test_drops_multiple_requests(self):
        r = {"method": "GET", "path": ["{{BaseURL}}/"], "matchers": [{"type": "status", "status": [200]}]}
        self.assertIsNone(convert(tmpl(http=[r, r])))

    def test_drops_payloads_and_extra_keys(self):
        self.assertIsNone(convert(tmpl(http=[{"method": "GET", "path": ["{{BaseURL}}/"],
                                             "payloads": {"x": ["1"]},
                                             "matchers": [{"type": "status", "status": [200]}]}])))

    def test_drops_denied_tags(self):
        self.assertIsNone(convert(tmpl(info={"name": "x", "severity": "high", "tags": "cve,fuzz"})))

    def test_drops_negative_matcher(self):
        self.assertIsNone(convert(tmpl(http=[{"method": "GET", "path": ["{{BaseURL}}/"],
                                             "matchers": [{"type": "word", "part": "body",
                                                           "words": ["x"], "negative": True}]}])))

    def test_drops_template_injection_path(self):
        self.assertIsNone(convert(tmpl(http=[{"method": "GET", "path": ["{{BaseURL}}/{{interactsh-url}}"],
                                             "matchers": [{"type": "status", "status": [200]}]}])))

    def test_drops_unsupported_matcher_type(self):
        self.assertIsNone(convert(tmpl(http=[{"method": "GET", "path": ["{{BaseURL}}/"],
                                             "matchers": [{"type": "dsl", "dsl": ["1==1"]}]}])))

    def test_normalize_id(self):
        self.assertEqual(normalize_id("CVE-2021-41773"), "cve-2021-41773")


if __name__ == "__main__":
    unittest.main()
