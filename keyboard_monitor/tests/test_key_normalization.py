"""Unit tests for key-name normalization (models.py).

These tests lock down the classification tables that the specification calls
out, and verify the two robustness guarantees:

* unsupported / hardware-specific keys become ``Unknown / Unmapped`` instead of
  raising, and
* normalization is total (it accepts anything, never returns ``None``).
"""

from __future__ import annotations

import pytest

from keyboard_monitor.models import (
    EventType,
    KeyCategory,
    KeyGroup,
    KeyIdentity,
    ModifierState,
    ModifierTracker,
    new_session_id,
    normalize_key,
)


class TestLetters:
    @pytest.mark.parametrize("raw", list("abcdefghijklmnopqrstuvwxyz"))
    def test_lowercase_letters(self, raw: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == raw.upper()
        assert identity.category is KeyCategory.LETTER
        assert identity.group is KeyGroup.LETTERS

    @pytest.mark.parametrize("raw", list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    def test_uppercase_letters(self, raw: str) -> None:
        assert normalize_key(raw).display_name == raw

    def test_all_26_letters_present(self) -> None:
        """Every letter A-Z must normalize, with nothing left unmapped."""
        normalized = {normalize_key(chr(code)).display_name for code in range(ord("a"), ord("z") + 1)}
        assert normalized == {chr(code) for code in range(ord("A"), ord("Z") + 1)}
        assert all(normalize_key(letter).category is KeyCategory.LETTER for letter in normalized)


class TestNumberRow:
    @pytest.mark.parametrize("digit", list("0123456789"))
    def test_number_row(self, digit: str) -> None:
        identity = normalize_key(digit)
        assert identity.display_name == digit
        assert identity.category is KeyCategory.NUMBER

    @pytest.mark.parametrize("shifted,digit", list(zip("!@#$%^&*()", "1234567890")))
    def test_shifted_symbols_map_to_number_row(self, shifted: str, digit: str) -> None:
        """'!' is shift+1, so it classifies as the number-row key 1."""
        identity = normalize_key(shifted)
        assert identity.display_name == digit
        assert identity.category is KeyCategory.NUMBER


class TestPunctuation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("-", "-"), ("_", "-"), ("=", "="), ("+", "="),
            ("[", "["), ("{", "["), ("]", "]"), ("}", "]"),
            ("\\", "\\"), ("|", "\\"), (";", ";"), (":", ";"),
            ("'", "'"), ('"', "'"), (",", ","), ("<", ","),
            (".", "."), (">", "."), ("/", "/"), ("?", "/"),
            ("`", "`"), ("~", "`"),
        ],
    )
    def test_punctuation_and_symbols(self, raw: str, expected: str) -> None:
        """All 22 punctuation/symbol keys from the specification."""
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.PUNCTUATION


class TestFunctionKeys:
    @pytest.mark.parametrize("index", range(1, 13))
    def test_f1_to_f12(self, index: int) -> None:
        identity = normalize_key(f"f{index}")
        assert identity.display_name == f"F{index}"
        assert identity.category is KeyCategory.FUNCTION
        assert identity.group is KeyGroup.FUNCTION


class TestModifiers:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("esc", "Esc"), ("Esc", "Esc"),
            ("tab", "Tab"), ("Tab", "Tab"),
            ("caps lock", "Caps Lock"), ("capslock", "Caps Lock"),
            ("shift", "Shift Left"), ("shift left", "Shift Left"),
            ("shift right", "Shift Right"),
            ("ctrl", "Ctrl Left"), ("ctrl left", "Ctrl Left"),
            ("ctrl right", "Ctrl Right"), ("control", "Ctrl Left"),
            ("alt", "Alt Left"), ("alt left", "Alt Left"),
            ("alt right", "Alt Right"), ("alt gr", "AltGr"), ("altgr", "AltGr"),
            ("win", "Windows Left"), ("win left", "Windows Left"),
            ("super left", "Windows Left"), ("cmd", "Windows Left"),
            ("win right", "Windows Right"), ("super right", "Windows Right"),
            ("menu", "Menu"), ("apps", "Menu"),
        ],
    )
    def test_modifier_keys(self, raw: str, expected: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.MODIFIER
        assert identity.is_modifier

    def test_side_suffix_splitting(self) -> None:
        """A 'base + side' name resolves even without an explicit alias."""
        assert normalize_key("shift    left").display_name == "Shift Left"
        assert normalize_key("Ctrl Right").display_name == "Ctrl Right"


class TestNavigationAndArrows:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("backspace", "Backspace"), ("enter", "Enter"), ("return", "Enter"),
            ("space", "Space"), ("spacebar", "Space"),
            ("insert", "Insert"), ("delete", "Delete"), ("home", "Home"),
            ("end", "End"), ("page up", "Page Up"), ("page down", "Page Down"),
        ],
    )
    def test_editing_navigation(self, raw: str, expected: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.NAVIGATION

    @pytest.mark.parametrize(
        "raw,expected",
        [("up", "Up"), ("down", "Down"), ("left", "Left"), ("right", "Right"),
         ("up arrow", "Up"), ("down arrow", "Down")],
    )
    def test_arrow_keys(self, raw: str, expected: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.ARROW


class TestNumpad:
    @pytest.mark.parametrize("digit", list("0123456789"))
    def test_numpad_digits(self, digit: str) -> None:
        for raw in (f"num {digit}", f"numpad {digit}"):
            identity = normalize_key(raw)
            assert identity.display_name == f"Numpad {digit}"
            assert identity.category is KeyCategory.NUMPAD

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("num lock", "Num Lock"),
            ("add", "Numpad +"), ("subtract", "Numpad -"),
            ("multiply", "Numpad *"), ("divide", "Numpad /"),
            ("decimal", "Numpad ."), ("enter (numpad)", "Numpad Enter"),
        ],
    )
    def test_numpad_functional_keys(self, raw: str, expected: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.NUMPAD

    def test_numpad_digits_are_not_confused_with_number_row(self) -> None:
        """'5' (number row) and 'num 5' (numpad) must stay distinct."""
        assert normalize_key("5").category is KeyCategory.NUMBER
        assert normalize_key("num 5").category is KeyCategory.NUMPAD


class TestOtherKeys:
    @pytest.mark.parametrize(
        "raw,expected",
        [("print screen", "Print Screen"), ("scroll lock", "Scroll Lock"),
         ("pause", "Pause"), ("pause/break", "Pause")],
    )
    def test_other_common_keys(self, raw: str, expected: str) -> None:
        identity = normalize_key(raw)
        assert identity.display_name == expected
        assert identity.category is KeyCategory.OTHER


class TestUnmappedHandling:
    @pytest.mark.parametrize(
        "raw",
        [
            "", "   ", None, "unidentified 00 FF 2A", "unidentified 8B 01",
            "totally made up key", "vkey_9999", 12345, b"\xff\xfe", object(),
        ],
    )
    def test_unmapped_keys_are_graceful(self, raw: object) -> None:
        """Unknown/hardware-specific keys must never raise or return None."""
        identity = normalize_key(raw)
        assert isinstance(identity, KeyIdentity)
        assert identity.display_name == "Unknown / Unmapped"
        assert identity.category is KeyCategory.UNKNOWN
        assert identity.group is KeyGroup.UNKNOWN
        assert not identity.is_modifier


class TestModifierState:
    def test_default_state_renders_as_none(self) -> None:
        assert ModifierState().as_string() == "None"
        assert ModifierState().is_empty()

    def test_combined_modifiers(self) -> None:
        state = ModifierState(ctrl=True, shift=True, caps_lock=True)
        assert state.as_string() == "Ctrl+Shift+CapsLock"

    def test_tracker_tracks_press_and_release(self) -> None:
        tracker = ModifierTracker()
        assert tracker.snapshot().as_string() == "None"

        state = tracker.press(normalize_key("ctrl left"))
        assert state.ctrl is True
        state = tracker.press(normalize_key("shift"))
        assert state.shift is True
        assert state.as_string() == "Ctrl+Shift"

        state = tracker.release(normalize_key("ctrl left"))
        assert state.ctrl is False
        assert state.as_string() == "Shift"

    def test_tracker_handles_lock_toggle(self) -> None:
        tracker = ModifierTracker()
        identity = normalize_key("caps lock")
        assert tracker.press(identity).caps_lock is True
        assert tracker.press(identity).caps_lock is False  # toggles back off

    def test_reset_clears_everything(self) -> None:
        tracker = ModifierTracker()
        tracker.press(normalize_key("alt left"))
        tracker.press(normalize_key("caps lock"))
        tracker.reset()
        assert tracker.snapshot().as_string() == "None"


class TestEventTypeEnum:
    def test_event_type_values(self) -> None:
        assert EventType.KEY_DOWN.value == "KEY_DOWN"
        assert EventType.KEY_UP.value == "KEY_UP"


class TestSessionId:
    def test_session_ids_are_unique_and_well_formed(self) -> None:
        from keyboard_monitor.security import is_valid_session_id

        ids = {new_session_id() for _ in range(200)}
        assert len(ids) == 200
        assert all(is_valid_session_id(value) for value in ids)