# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from settings_drift import find_drift


def ruleset(name, *rules):
    return {"name": name, "enforcement": "active", "rules": list(rules)}


class FindDriftTest(unittest.TestCase):
    def test_undeclared_live_keys_are_ignored(self):
        self.assertEqual(find_drift({"private": False}, {"private": False, "id": 7}), [])

    def test_changed_scalar_is_drift(self):
        self.assertEqual(
            find_drift({"repository": {"private": False}}, {"repository": {"private": True}}),
            ["repository.private: expected False, found True"],
        )

    def test_missing_key_is_drift(self):
        self.assertEqual(find_drift({"has_wiki": False}, {}), ["has_wiki: missing"])

    def test_plain_lists_compare_without_order(self):
        self.assertEqual(find_drift({"include": ["a", "b"]}, {"include": ["b", "a"]}), [])

    def test_ruleset_present_live_but_not_declared_is_drift(self):
        self.assertEqual(
            find_drift({"rulesets": [ruleset("a")]}, {"rulesets": [ruleset("a"), ruleset("b")]}),
            ["rulesets[b]: present live, not declared"],
        )

    def test_rule_removed_live_is_drift(self):
        desired = {"rulesets": [ruleset("a", {"type": "deletion"}, {"type": "required_signatures"})]}
        live = {"rulesets": [ruleset("a", {"type": "deletion"})]}
        self.assertEqual(find_drift(desired, live), ["rulesets[a].rules[required_signatures]: missing"])

    def test_rule_parameter_change_is_drift(self):
        desired = {"rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 0}}]}
        live = {"rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 2, "x": 1}}]}
        self.assertEqual(
            find_drift(desired, live),
            ["rules[pull_request].parameters.required_approving_review_count: expected 0, found 2"],
        )

    def test_extra_status_check_live_is_drift(self):
        desired = {"checks": [{"context": "nextest"}]}
        live = {"checks": [{"context": "nextest"}, {"context": "extra", "integration_id": 1}]}
        self.assertEqual(find_drift(desired, live), ["checks[extra]: present live, not declared"])

    def test_empty_declared_list_rejects_live_entries(self):
        self.assertEqual(
            find_drift({"bypass_actors": []}, {"bypass_actors": [{"actor_id": 5}]}),
            ["bypass_actors: expected [], found [{'actor_id': 5}]"],
        )


if __name__ == "__main__":
    unittest.main()
