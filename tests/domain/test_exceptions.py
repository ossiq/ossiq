"""Tests for domain/exceptions.py — the shared ApplicationError rendering."""

from ossiq.domain.exceptions import ApplicationError, UnknownProjectPackageManager


class TestApplicationErrorRender:
    """One formatter for both front doors: mcp/server.py used to carry its own copy, marked
    'Mirrors cli.py's error_boundary()'."""

    def test_title_and_message(self):
        assert ApplicationError("something broke").render() == "Error: something broke"

    def test_hint_goes_on_its_own_line(self):
        rendered = ApplicationError("something broke", hint="try --traceback").render()

        assert rendered == "Error: something broke\ntry --traceback"

    def test_subclass_title_and_class_level_hint_are_used(self):
        rendered = UnknownProjectPackageManager("Unable to identify Package Manager for .").render()

        assert rendered.startswith("Unknown Package Manager: Unable to identify Package Manager for .")
        assert "ossiq supports" in rendered

    def test_empty_message_still_names_the_title(self):
        assert ApplicationError().render() == "Error: "
