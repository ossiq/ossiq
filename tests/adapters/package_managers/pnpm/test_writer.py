"""
Tests for pnpm/writer.py: catalog ranges and overrides written into pnpm-workspace.yaml without
disturbing what the user wrote around them.
"""

from pathlib import Path

import pytest

from ossiq.adapters.package_managers.pnpm.writer import (
    append_entry,
    dump_workspace,
    edit_workspace,
    load_workspace,
    sync_mapping,
    write_catalog_specs,
    write_workspace_overrides,
)
from ossiq.domain.exceptions import PackageManagerExecutionError
from tests.adapters.package_managers.npm.helpers import make_npm_update_entry, make_npm_update_plan

WORKSPACE_FIXTURE = Path(__file__).parents[4] / "testdata" / "pnpm" / "workspace-config" / "pnpm-workspace.yaml"


def ms_plan(current: str = "2.1.2", recommended: str = "2.1.3"):
    return make_npm_update_plan(transitive=[make_npm_update_entry("ms", current, recommended, is_direct=False)])


class TestLoadWorkspace:
    @pytest.mark.parametrize(
        "text", [None, "", "  \n", "# only a comment\n"], ids=["none", "empty", "blank", "comment"]
    )
    def test_a_missing_or_empty_file_reads_as_an_empty_mapping(self, text):
        assert load_workspace(text) == {}

    def test_invalid_yaml_raises_a_clean_error(self):
        with pytest.raises(PackageManagerExecutionError, match="pnpm-workspace.yaml is not valid YAML"):
            load_workspace("overrides: [unclosed\n")

    def test_a_document_that_is_not_a_mapping_raises_a_clean_error(self):
        with pytest.raises(PackageManagerExecutionError, match="mapping"):
            load_workspace("- a\n- b\n")

    def test_the_workspace_fixture_round_trips_byte_for_byte(self):
        """Guards the indent, width and quote settings: comments, quoted keys and `  - item` survive."""
        text = WORKSPACE_FIXTURE.read_text()
        assert dump_workspace(load_workspace(text)) == text

    def test_quoted_values_stay_quoted(self):
        text = "catalog:\n  react: \"^18.2.0\"\n  vue: '^3.0.0'\n"
        assert dump_workspace(load_workspace(text)) == text


BLOCK_LAYOUTS = {
    "blank line before the next block": (
        "overrides:\n  foo: 1.0.0\n\ncatalog:\n  react: ^18\n",
        "overrides:\n  foo: 1.0.0\n  new: 2.0.0\n\ncatalog:\n  react: ^18\n",
    ),
    "heading comment of the next block": (
        "overrides:\n  foo: 1.0.0\n\n# Cooldown\nminimumReleaseAge: 1\n",
        "overrides:\n  foo: 1.0.0\n  new: 2.0.0\n\n# Cooldown\nminimumReleaseAge: 1\n",
    ),
    "inline comment on the last entry": (
        "overrides:\n  foo: 1.0.0 # keep\n\ncatalog:\n  react: ^18\n",
        "overrides:\n  foo: 1.0.0 # keep\n  new: 2.0.0\n\ncatalog:\n  react: ^18\n",
    ),
    "inline comment then a heading comment": (
        "overrides:\n  foo: 1.0.0 # keep\n\n# Cooldown\nminimumReleaseAge: 1\n",
        "overrides:\n  foo: 1.0.0 # keep\n  new: 2.0.0\n\n# Cooldown\nminimumReleaseAge: 1\n",
    ),
    "no blank line before the next block": (
        "overrides:\n  foo: 1.0.0\ncatalog:\n  react: ^18\n",
        "overrides:\n  foo: 1.0.0\n  new: 2.0.0\ncatalog:\n  react: ^18\n",
    ),
    "last block of the file": (
        "overrides:\n  foo: 1.0.0\n",
        "overrides:\n  foo: 1.0.0\n  new: 2.0.0\n",
    ),
    "last block of the file with an inline comment": (
        "overrides:\n  foo: 1.0.0 # keep\n",
        "overrides:\n  foo: 1.0.0 # keep\n  new: 2.0.0\n",
    ),
}


class TestAppendEntry:
    @pytest.mark.parametrize("before, after", BLOCK_LAYOUTS.values(), ids=BLOCK_LAYOUTS.keys())
    def test_what_follows_the_block_stays_after_the_new_entry(self, before, after):
        workspace = load_workspace(before)
        append_entry(workspace["overrides"], "new", "2.0.0")
        assert dump_workspace(workspace) == after

    def test_a_new_top_level_key_goes_after_the_last_one(self):
        workspace = load_workspace("packages:\n  - a\n")
        append_entry(workspace, "overrides", {"new": "2.0.0"})
        assert dump_workspace(workspace) == "packages:\n  - a\noverrides:\n  new: 2.0.0\n"


class TestSyncMapping:
    def test_replacing_the_last_entry_keeps_the_blank_line_before_the_next_block(self):
        workspace = load_workspace("overrides:\n  foo: 1.0.0\n\ncatalog:\n  react: ^18\n")
        sync_mapping(workspace["overrides"], {"new": "2.0.0"})
        assert dump_workspace(workspace) == "overrides:\n  new: 2.0.0\n\ncatalog:\n  react: ^18\n"

    def test_a_changed_value_is_edited_in_place_with_its_comment(self):
        workspace = load_workspace("overrides:\n  foo: 1.0.0 # keep\n  bar: 1.0.0\n")
        sync_mapping(workspace["overrides"], {"foo": "1.1.0", "bar": "1.0.0"})
        assert dump_workspace(workspace) == "overrides:\n  foo: 1.1.0 # keep\n  bar: 1.0.0\n"


class TestWriteCatalogSpecs:
    @staticmethod
    def bump(workspace_text: str, spec: str, *, forced: bool = False, pin_all: bool = False) -> str:
        entry = make_npm_update_entry("react", "18.3.1", "18.4.0", version_defined=spec, is_forced=forced)
        workspace = load_workspace(workspace_text)
        write_catalog_specs(
            {"dependencies": {"react": spec}}, workspace, make_npm_update_plan(direct=[entry], pin_all=pin_all)
        )
        return dump_workspace(workspace)

    @pytest.mark.parametrize(
        "workspace_text, spec",
        [
            ("catalog:\n  react: ^18.2.0\n", "catalog:"),
            ("catalog:\n  react: ^18.2.0\n", "catalog:default"),
            ("catalogs:\n  default:\n    react: ^18.2.0\n", "catalog:"),
            ("catalogs:\n  react18:\n    react: ^18.2.0\n", "catalog:react18"),
        ],
        ids=["default-key", "default-by-name", "catalogs-default", "named"],
    )
    def test_the_range_is_relaxed_in_the_catalog_that_holds_it(self, workspace_text, spec):
        assert self.bump(workspace_text, spec) == workspace_text.replace("^18.2.0", "^18.4.0")

    def test_a_forced_entry_is_pinned_exact(self):
        assert self.bump("catalog:\n  react: ^18.2.0\n", "catalog:", forced=True) == "catalog:\n  react: 18.4.0\n"

    def test_pin_all_pins_exact(self):
        assert self.bump("catalog:\n  react: ^18.2.0\n", "catalog:", pin_all=True) == "catalog:\n  react: 18.4.0\n"

    def test_a_quoted_range_stays_quoted(self):
        assert self.bump('catalog:\n  react: "^18.2.0"\n', "catalog:") == 'catalog:\n  react: "^18.4.0"\n'

    @pytest.mark.parametrize(
        "workspace_text",
        ["catalog:\n  vue: ^3.0.0\n", "catalogs:\n  other:\n    react: ^18.2.0\n", ""],
        ids=["entry-missing", "catalog-missing", "no-workspace"],
    )
    def test_a_catalog_or_entry_that_is_not_there_is_left_for_pnpm_to_report(self, workspace_text):
        assert self.bump(workspace_text, "catalog:") == dump_workspace(load_workspace(workspace_text))

    def test_a_dependency_that_does_not_use_a_catalog_is_ignored(self):
        text = "catalog:\n  react: ^18.2.0\n"
        assert self.bump(text, "^18.0.0") == text


class TestWriteWorkspaceOverrides:
    @staticmethod
    def write(workspace_text: str | None, plan, pkg: dict | None = None):
        pkg = {"name": "app"} if pkg is None else pkg
        workspace = load_workspace(workspace_text)
        write_workspace_overrides(pkg, workspace, plan)
        return pkg, dump_workspace(workspace)

    def test_a_first_override_creates_the_block_and_the_record(self):
        pkg, text = self.write("packages:\n  - a\n", ms_plan())
        assert text == "packages:\n  - a\noverrides:\n  ms@2.1.2: 2.1.3\n"
        assert pkg["ossiq:metadata"] == {"overrides": {"ms@2.1.2": "2.1.3"}}
        assert "overrides" not in pkg

    def test_an_empty_overrides_key_is_filled_in_place(self):
        _, text = self.write("overrides:\npackages:\n  - a\n", ms_plan())
        assert text == "overrides:\n  ms@2.1.2: 2.1.3\npackages:\n  - a\n"

    def test_the_users_rules_are_kept_beside_the_new_one(self):
        _, text = self.write("overrides:\n  lodash: 4.17.0 # pinned\n", ms_plan())
        assert text == "overrides:\n  lodash: 4.17.0 # pinned\n  ms@2.1.2: 2.1.3\n"

    def test_a_bump_replaces_the_rule_oss_iq_wrote_for_the_same_copy(self):
        pkg = {"ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}}}
        pkg, text = self.write("overrides:\n  ms@2.1.2: 2.1.3\n", ms_plan("2.1.3", "2.1.5"), pkg)
        assert text == "overrides:\n  ms@2.1.3: 2.1.5\n"
        assert pkg["ossiq:metadata"]["overrides"] == {"ms@2.1.3": "2.1.5"}

    def test_a_key_the_user_edited_since_is_left_alone(self):
        pkg = {"ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}}}
        pkg, text = self.write("overrides:\n  ms@2.1.2: 2.0.0\n", ms_plan(), pkg)
        assert text == "overrides:\n  ms@2.1.2: 2.0.0\n"
        assert pkg["ossiq:metadata"] == {"overrides": {"ms@2.1.2": "2.1.3"}}

    def test_a_scoped_key_the_user_wrote_governs_the_copy(self):
        pkg, text = self.write('overrides:\n  "debug@4>ms": 2.1.3\n', ms_plan())
        assert text == 'overrides:\n  "debug@4>ms": 2.1.3\n'
        assert "ossiq:metadata" not in pkg

    def test_overrides_that_are_not_a_mapping_raise_instead_of_being_replaced(self):
        with pytest.raises(PackageManagerExecutionError, match="not a mapping"):
            self.write("overrides:\n  - a\n", ms_plan())

    def test_a_plan_without_transitive_entries_changes_nothing(self):
        pkg, text = self.write("overrides:\n  lodash: 4.17.0\n", make_npm_update_plan())
        assert text == "overrides:\n  lodash: 4.17.0\n"
        assert pkg == {"name": "app"}


class TestEditWorkspace:
    def test_a_plan_that_changes_nothing_there_yields_no_text(self):
        assert edit_workspace(WORKSPACE_FIXTURE.read_text(), {"name": "app"}, make_npm_update_plan()) is None
        assert edit_workspace(None, {"name": "app"}, make_npm_update_plan()) is None

    def test_a_project_without_a_workspace_file_gets_a_new_one(self):
        assert edit_workspace(None, {"name": "app"}, ms_plan()) == "overrides:\n  ms@2.1.2: 2.1.3\n"

    def test_the_fixture_keeps_every_comment_and_gains_one_line(self):
        text = WORKSPACE_FIXTURE.read_text()
        plan = make_npm_update_plan(transitive=[make_npm_update_entry("semver", "7.0.0", "7.5.2", is_direct=False)])

        edited = edit_workspace(text, {"name": "app"}, plan)

        assert edited is not None
        assert edited.replace("  semver@7.0.0: 7.5.2\n", "") == text
