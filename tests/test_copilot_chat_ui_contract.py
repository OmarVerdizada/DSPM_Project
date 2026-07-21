from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.copilot import memory


def _run(awaitable):
    return asyncio.run(awaitable)


class CopilotConversationEditMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(memory, "DATA_DIR", Path(self.temp.name))
        self.data_patch.start()

    def tearDown(self) -> None:
        self.data_patch.stop()
        self.temp.cleanup()

    def test_truncate_conversation_removes_edited_turn_and_every_later_message(self) -> None:
        tenant = "edit-tenant"
        conversation = "edit-conversation"
        _run(memory.save_turn(tenant, conversation, "first question", "first answer", [], []))
        _run(memory.save_turn(tenant, conversation, "old second question", "old second answer", [], []))
        _run(memory.save_turn(tenant, conversation, "third question", "third answer", [], []))

        truncate = getattr(memory, "truncate_conversation", None)
        self.assertIsNotNone(truncate, "memory.truncate_conversation is required")
        result = _run(truncate(tenant, conversation, 1))
        messages = _run(memory.load_full_conversation(tenant, conversation))

        self.assertEqual(result["kept_messages"], 2)
        self.assertEqual(result["removed_messages"], 4)
        self.assertEqual([row["content"] for row in messages], ["first question", "first answer"])

    def test_truncate_rejects_an_out_of_range_user_turn(self) -> None:
        tenant = "edit-range-tenant"
        conversation = "edit-range-conversation"
        _run(memory.save_turn(tenant, conversation, "first question", "first answer", [], []))

        truncate = getattr(memory, "truncate_conversation", None)
        self.assertIsNotNone(truncate, "memory.truncate_conversation is required")
        with self.assertRaises(IndexError):
            _run(truncate(tenant, conversation, 3))


class CopilotFrontendInteractionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = Path("frontend/copilot.js").read_text(encoding="utf-8")
        cls.styles = Path("frontend/copilot.css").read_text(encoding="utf-8")
        cls.html = Path("frontend/index.html").read_text(encoding="utf-8")
        cls.router = Path("backend/copilot/router.py").read_text(encoding="utf-8")

    def test_notification_has_separate_dismiss_control_and_endpoint(self) -> None:
        self.assertIn("data-insight-dismiss", self.script)
        self.assertIn("/dismiss", self.script)
        self.assertIn("stopPropagation()", self.script)
        self.assertIn("copilot-insight-dismiss", self.styles)

    def test_notification_body_still_invokes_the_action_endpoint(self) -> None:
        self.assertIn("data-insight-action", self.script)
        self.assertIn("/action", self.script)

    def test_dismissed_notifications_are_stable_for_the_ui_session(self) -> None:
        self.assertIn("dspm-copilot-dismissed-insights", self.script)
        self.assertIn("sessionStorage", self.script)

    def test_edit_is_inline_and_uses_replacement_endpoint(self) -> None:
        self.assertIn("copilot-inline-editor", self.script)
        self.assertIn("data-copilot-action=\"save-edit\"", self.script)
        self.assertIn("data-copilot-action=\"cancel-edit\"", self.script)
        self.assertIn("method = \"PUT\"", self.script)
        self.assertIn("@router.put(\"/conversations/{conversation_id}/messages/{turn_index}\"", self.router)

    def test_edit_removes_downstream_messages_without_appending_user_bubble(self) -> None:
        self.assertIn("removeMessagesAfter", self.script)
        self.assertIn("replaceMessage", self.script)
        self.assertNotIn("input.value = raw;\n        input.dispatchEvent", self.script)

    def test_copy_action_is_preserved(self) -> None:
        self.assertIn('data-copilot-action="copy"', self.script)
        self.assertIn('data-copilot-action="edit"', self.script)
        self.assertIn("copyToClipboard(copyableMessageText", self.script)

    def test_assistant_messages_have_copy_only_actions(self) -> None:
        self.assertIn("ASSISTANT_MESSAGE_ACTIONS_HTML", self.script)
        self.assertIn('aria-label="Copy answer"', self.script)
        self.assertIn('role === "user" ? USER_MESSAGE_ACTIONS_HTML : ASSISTANT_MESSAGE_ACTIONS_HTML', self.script)

    def test_assistant_copy_uses_visible_body_text_only(self) -> None:
        self.assertIn("function copyableMessageText", self.script)
        self.assertIn(".copilot-message-body", self.script)
        self.assertIn("innerText", self.script)
        self.assertNotIn("copyToClipboard(raw)", self.script)

    def test_internal_tool_names_are_not_rendered_in_visible_status(self) -> None:
        self.assertNotIn('tools_used.join', self.script)
        self.assertNotIn('Grounded response - ${escape', self.script)
        self.assertNotIn('Grounded response · ${escape', self.script)
        self.assertNotIn('Grounded in authorized scan evidence', self.script)
        self.assertIn('clearResponseStatus', self.script)
        self.assertIn('.copilot-meta:empty', self.styles)

    def test_report_links_render_as_functional_message_actions(self) -> None:
        self.assertIn("copilot-report-action", self.script)
        self.assertIn("copilot-report-action", self.styles)
        self.assertIn("Download report", self.script)

    def test_message_scroller_keeps_clearance_above_composer(self) -> None:
        self.assertRegex(self.styles, r"\.copilot-messages\s*\{[^}]*padding:[^;}]*[2-9][0-9]px")
        self.assertIn("scroll-padding-bottom", self.styles)

    def test_composer_autosize_resets_after_send(self) -> None:
        self.assertIn("function resetComposerHeight", self.script)
        self.assertRegex(
            self.script,
            r'input\.value\s*=\s*"";\s*resetComposerHeight\(\);\s*ask\(text\);',
        )
        self.assertIn('input.style.overflowY = input.scrollHeight > COMPOSER_MAX_HEIGHT ? "auto" : "hidden"', self.script)
        self.assertIn('input.style.overflowY = "hidden"', self.script)

    def test_copilot_layout_constrains_messages_and_composer(self) -> None:
        self.assertRegex(
            self.styles,
            r"\.copilot-popup\s*\{[^}]*display:\s*flex;[^}]*flex-direction:\s*column;[^}]*overflow:\s*hidden;",
        )
        self.assertRegex(
            self.styles,
            r"\.copilot-messages\s*\{[^}]*flex:\s*1 1 auto;[^}]*min-height:\s*0;[^}]*overflow-y:\s*auto;",
        )
        self.assertRegex(self.styles, r"\.copilot-form\s*\{[^}]*flex-shrink:\s*0;")
        self.assertRegex(
            self.styles,
            r"\.copilot-composer textarea\s*\{[^}]*min-height:\s*26px;[^}]*max-height:\s*118px;[^}]*overflow-y:\s*hidden;",
        )
        self.assertRegex(self.styles, r"\.copilot-message\s*\{[^}]*flex:\s*0 0 auto;")

    def test_inline_editor_sizing_stays_scoped_from_main_composer(self) -> None:
        self.assertIn(".copilot-inline-editor textarea", self.styles)
        self.assertIn(".copilot-composer textarea", self.styles)
        self.assertNotIn(".copilot-inline-editor textarea,\n.copilot-composer textarea", self.styles)

    def test_assistant_bubbles_are_content_sized_without_action_footer_space(self) -> None:
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.assistant\s*\{[^}]*align-items:\s*flex-start;[^}]*max-width:\s*calc\(100% - 32px\);",
        )
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.assistant \.copilot-message-body\s*\{[^}]*width:\s*fit-content;[^}]*max-width:\s*100%;[^}]*height:\s*auto;[^}]*min-height:\s*0;",
        )
        self.assertNotIn(".copilot-message.has-actions .copilot-message-body", self.styles)
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.assistant \.copilot-message-actions\s*\{[^}]*left:\s*calc\(100% \+ 6px\);[^}]*right:\s*auto;",
        )

    def test_user_bubbles_are_content_sized_without_action_footer_space(self) -> None:
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.user\s*\{[^}]*align-self:\s*flex-end;[^}]*align-items:\s*flex-start;[^}]*max-width:\s*calc\(100% - 58px\);",
        )
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.user \.copilot-message-body\s*\{[^}]*width:\s*fit-content;[^}]*max-width:\s*100%;[^}]*height:\s*auto;[^}]*min-height:\s*0;",
        )
        self.assertNotIn(".copilot-message.user.has-actions .copilot-message-body", self.styles)
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.user \.copilot-message-actions\s*\{[^}]*right:\s*calc\(100% \+ 6px\);",
        )
        self.assertRegex(
            self.styles,
            r"\.copilot-message\.user \.copilot-message-actions button\s*\{[^}]*background:\s*color-mix\([^}]*color:\s*var\(--muted\)",
        )
        self.assertIn(".copilot-message.is-editing > .copilot-message-content > .copilot-message-actions", self.styles)
        self.assertIn(".copilot-inline-editor textarea", self.styles)

    def test_dashboard_references_the_polished_copilot_assets(self) -> None:
        self.assertIn('/static/copilot.css?v=13', self.html)
        self.assertIn('/static/copilot.js?v=8', self.html)


if __name__ == "__main__":
    unittest.main()
