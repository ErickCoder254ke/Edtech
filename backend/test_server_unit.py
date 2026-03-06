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
        # Declared MIME mismatches are tolerated for txt if content signature is valid.
        detected = server.detect_mime(b"hello world", "txt", "application/pdf")
        self.assertEqual(detected, "text/plain")

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
        self.assertIn("format validation failed", str(ctx.exception.detail).lower())

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
        self.assertIn("SECTION A", prompt)
        self.assertIn("SECTION B", prompt)
        self.assertIn("SECTION C", prompt)
        self.assertIn("candidate_details", prompt)
        self.assertIn("at least 20 total questions", prompt)

    def test_build_prompt_mentions_paper_two_when_requested(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=40,
            additional_instructions="Generate Paper 2 practical",
        )
        prompt = server.build_prompt(req, context="sample context")
        self.assertIn("Paper variant: Paper 2 (practical)", prompt)

    def test_exam_quality_enforces_mark_scheme_and_paper_variant(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=40,
            additional_instructions="Paper 2 practical only",
            num_questions=4,
        )
        payload = {
            "school_name": "Sample School",
            "exam_title": "Sample",
            "subject": "Computer Studies",
            "class_level": "Form 4",
            "total_marks": 40,
            "time_allowed": "2h",
            "instructions": ["Answer all questions."],
            "sections": [
                {
                    "section_name": "",
                    "questions": [
                        {"question_number": "1", "question_text": "Set margins in a document", "marks": 10, "type": "structured", "mark_scheme": ""},
                        {"question_number": "2", "question_text": "Create a table with 4 columns", "marks": 10, "type": "structured", "mark_scheme": ""},
                        {"question_number": "3", "question_text": "Sort records by score", "marks": 10, "type": "structured", "mark_scheme": ""},
                        {"question_number": "4", "question_text": "Apply formulas in spreadsheet", "marks": 10, "type": "structured", "mark_scheme": ""},
                    ],
                }
            ],
        }
        normalized = server.enforce_assessment_output_quality("exam", payload, request=req)
        first = normalized["sections"][0]["questions"][0]
        self.assertEqual(first["type"], "practical")
        self.assertTrue(str(first["mark_scheme"]).strip())

    def test_exam_quality_requires_kenyan_three_section_blueprint(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=60,
            num_questions=20,
        )
        payload = {
            "school_name": "Sample School",
            "exam_title": "Sample",
            "subject": "Science",
            "class_level": "Grade 6",
            "total_marks": 60,
            "time_allowed": "1h 30m",
            "instructions": ["Answer questions."],
            "sections": [
                {
                    "section_name": "Only Section",
                    "questions": [
                        {"question_number": str(i + 1), "question_text": f"Question {i+1}?", "marks": 3, "type": "structured", "mark_scheme": "points"}
                        for i in range(12)
                    ],
                }
            ],
        }
        with self.assertRaises(HTTPException) as ctx:
            server.enforce_assessment_output_quality("exam", payload, request=req)
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertIn("Kenyan section blueprint", str(ctx.exception.detail))

    def test_exam_quality_adds_candidate_details_and_instruction_defaults(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=50,
            num_questions=20,
        )
        payload = {
            "school_name": "Sample School",
            "exam_title": "End Term Exam",
            "subject": "Mathematics",
            "class_level": "Grade 7",
            "total_marks": 50,
            "time_allowed": "2 hours",
            "instructions": ["Write your name."],
            "sections": [
                {"section_name": "SECTION A", "questions": [{"question_number": str(i + 1), "question_text": f"Short question {i+1}?", "marks": 1, "type": "mcq", "options": ["A", "B", "C", "D"], "mark_scheme": "correct answer"} for i in range(10)]},
                {"section_name": "SECTION B", "questions": [{"question_number": str(i + 1), "question_text": f"Structured question {i+1}?", "marks": 4, "type": "structured", "sub_questions": ["(a) One", "(b) Two"], "mark_scheme": "points"} for i in range(5)]},
                {"section_name": "SECTION C", "questions": [{"question_number": str(i + 1), "question_text": f"Essay question {i+1}?", "marks": 10, "type": "essay", "mark_scheme": "points"} for i in range(2)]},
            ],
        }
        normalized = server.enforce_assessment_output_quality("exam", payload, request=req)
        self.assertEqual(len(normalized["sections"]), 3)
        self.assertGreaterEqual(len(normalized["instructions"]), 4)
        self.assertIn("candidate_details", normalized)
        self.assertIn("admission_number", normalized["candidate_details"])

    def test_build_prompt_mentions_paper_three_when_requested(self):
        req = server.GenerationRequest(
            document_ids=["d1"],
            generation_type="exam",
            marks=40,
            additional_instructions="Generate Paper 3 for Chemistry practical",
        )
        prompt = server.build_prompt(req, context="sample context")
        self.assertIn("Paper variant: Paper 3 (practical)", prompt)

    def test_apply_exam_constraints_section_pattern_for_history_paper_two(self):
        payload = {
            "school_name": "Sample School",
            "exam_title": "History Mock",
            "subject": "History",
            "class_level": "Form 4",
            "total_marks": 40,
            "time_allowed": "2h",
            "instructions": ["Answer questions"],
            "sections": [
                {"section_name": "", "questions": [{"question_number": "1", "question_text": "Q1", "marks": 10, "type": "essay", "mark_scheme": "points"}]},
                {"section_name": "", "questions": [{"question_number": "2", "question_text": "Q2", "marks": 10, "type": "essay", "mark_scheme": "points"}]},
                {"section_name": "", "questions": [{"question_number": "3", "question_text": "Q3", "marks": 10, "type": "essay", "mark_scheme": "points"}]},
            ],
        }
        normalized = server.apply_exam_constraints(
            payload,
            additional_instructions="History Paper 2",
        )
        self.assertEqual(normalized["sections"][0]["section_name"], "SECTION A")
        self.assertEqual(normalized["sections"][1]["section_name"], "SECTION B")
        self.assertEqual(normalized["sections"][2]["section_name"], "SECTION C")

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

    def test_is_llm_provider_configured_supports_groq(self):
        original = server.GROQ_API_KEY
        try:
            server.GROQ_API_KEY = "groq-test-key"
            self.assertTrue(server._is_llm_provider_configured("groq"))
            server.GROQ_API_KEY = ""
            self.assertFalse(server._is_llm_provider_configured("groq"))
        finally:
            server.GROQ_API_KEY = original

    def test_resolve_llm_providers_includes_groq(self):
        original_provider = server.LLM_PROVIDER
        original_providers = list(server.LLM_PROVIDERS)
        try:
            server.LLM_PROVIDER = "hybrid"
            server.LLM_PROVIDERS = ["groq", "gemini", "groq", "nvidia"]
            self.assertEqual(server._resolve_llm_providers(), ["groq", "gemini", "nvidia"])
        finally:
            server.LLM_PROVIDER = original_provider
            server.LLM_PROVIDERS = original_providers


if __name__ == "__main__":
    unittest.main()
