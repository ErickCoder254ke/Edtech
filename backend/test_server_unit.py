import unittest
import sys
import types

from fastapi import HTTPException

# Stub optional runtime dependencies so tests can import `server.py`
if "aiofiles" not in sys.modules:
    aiofiles_stub = types.ModuleType("aiofiles")
    sys.modules["aiofiles"] = aiofiles_stub

if "pypdf" not in sys.modules:
    pypdf_stub = types.ModuleType("pypdf")

    class _PdfReaderStub:
        def __init__(self, *_args, **_kwargs):
            self.pages = []

    pypdf_stub.PdfReader = _PdfReaderStub
    sys.modules["pypdf"] = pypdf_stub

if "docx" not in sys.modules:
    docx_stub = types.ModuleType("docx")

    class _DocumentStub:
        def __init__(self, *_args, **_kwargs):
            self.paragraphs = []

    docx_stub.Document = _DocumentStub
    sys.modules["docx"] = docx_stub

if "emergentintegrations" not in sys.modules:
    emergent_pkg = types.ModuleType("emergentintegrations")
    llm_pkg = types.ModuleType("emergentintegrations.llm")
    chat_pkg = types.ModuleType("emergentintegrations.llm.chat")

    class _UserMessageStub:
        def __init__(self, text: str):
            self.text = text

    class _LlmChatStub:
        def __init__(self, **_kwargs):
            pass

        def with_model(self, *_args, **_kwargs):
            return self

        async def send_message(self, _msg):
            return "{}"

    chat_pkg.LlmChat = _LlmChatStub
    chat_pkg.UserMessage = _UserMessageStub
    sys.modules["emergentintegrations"] = emergent_pkg
    sys.modules["emergentintegrations.llm"] = llm_pkg
    sys.modules["emergentintegrations.llm.chat"] = chat_pkg

import server


class TestServerGuards(unittest.TestCase):
    def test_detect_mime_pdf_valid(self):
        content = b"%PDF-1.7\n1 0 obj\n"
        detected = server.detect_mime(content, "pdf", "application/pdf")
        self.assertEqual(detected, "application/pdf")

    def test_detect_mime_reject_mismatch(self):
        with self.assertRaises(HTTPException) as ctx:
            server.detect_mime(b"%PDF-1.7\n", "docx", "application/pdf")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Invalid file content", str(ctx.exception.detail))

    def test_detect_mime_reject_bad_declared_type(self):
        with self.assertRaises(HTTPException) as ctx:
            server.detect_mime(b"hello world", "txt", "application/pdf")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("MIME type does not match", str(ctx.exception.detail))

    def test_token_budget_selects_prefix(self):
        chunks = [
            {"text": "a" * 40},   # ~10 tokens
            {"text": "b" * 80},   # ~20 tokens
            {"text": "c" * 400},  # ~100 tokens
        ]
        context = server.assemble_context_with_budget(chunks, max_tokens=35)
        self.assertIn("a" * 40, context)
        self.assertIn("b" * 80, context)
        self.assertNotIn("c" * 400, context)

    def test_token_budget_raises_when_none_fit(self):
        with self.assertRaises(HTTPException) as ctx:
            server.assemble_context_with_budget([{"text": "x" * 200}], max_tokens=10)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_quiz_schema_passes(self):
        payload = {
            "quiz": [
                {
                    "type": "mcq",
                    "question": "What is 2+2?",
                    "options": ["1", "2", "3", "4"],
                    "correct_answer": "4",
                    "marks": 1,
                    "explanation": "Basic arithmetic",
                }
            ]
        }
        validated = server.validate_structured_output("quiz", payload)
        self.assertEqual(validated["quiz"][0]["correct_answer"], "4")

    def test_validate_quiz_schema_rejects_bad_payload(self):
        with self.assertRaises(HTTPException) as ctx:
            server.validate_structured_output("quiz", {"quiz": [{"question": "Missing marks"}]})
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertIn("schema validation failed", str(ctx.exception.detail))

    def test_build_prompt_enforces_strict_json_for_quiz(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="quiz",
            num_questions=3,
        )
        prompt = server.build_prompt(req, context="sample context")
        self.assertIn("Return ONLY valid JSON", prompt)

    def test_build_prompt_enforces_strict_json_for_exam(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=50,
        )
        prompt = server.build_prompt(req, context="sample context")
        self.assertIn("Return ONLY valid JSON", prompt)
        self.assertIn("Ensure total marks equals 50", prompt)

    def test_normalize_topic_category_accepts_aliases(self):
        self.assertEqual(server.normalize_topic_category("Grade 1-4"), "grade_1_4")
        self.assertEqual(server.normalize_topic_category("junior_secondary"), "junior_secondary")

    def test_normalize_topic_category_rejects_unknown(self):
        with self.assertRaises(HTTPException) as ctx:
            server.normalize_topic_category("University")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Invalid category", str(ctx.exception.detail))

    def test_get_topic_sort_enforces_allowed_values(self):
        self.assertEqual(server.get_topic_sort("top"), [("upvote_count", -1), ("created_at", -1)])
        self.assertEqual(server.get_topic_sort("new"), [("created_at", -1)])
        with self.assertRaises(HTTPException) as ctx:
            server.get_topic_sort("old")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
