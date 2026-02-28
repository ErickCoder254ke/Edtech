import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

import '../models/models.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

enum _ViewMode { student, teacher }

class GenerationViewerScreen extends StatefulWidget {
  const GenerationViewerScreen({super.key, required this.generation});

  final GenerationResponse generation;

  @override
  State<GenerationViewerScreen> createState() => _GenerationViewerScreenState();
}

class _GenerationViewerScreenState extends State<GenerationViewerScreen> {
  _ViewMode _mode = _ViewMode.student;

  bool get _supportsModes =>
      widget.generation.generationType == 'quiz' ||
      widget.generation.generationType == 'exam';

  @override
  Widget build(BuildContext context) {
    final type = widget.generation.generationType;
    return Scaffold(
      appBar: AppBar(
        title: Text(_title(type)),
        actions: [
          IconButton(
            tooltip: 'Export PDF',
            onPressed: () => _exportCurrentAsPdf(context),
            icon: const Icon(Icons.picture_as_pdf_rounded),
          ),
          if (type == 'exam')
            IconButton(
              tooltip: 'Print Exam',
              onPressed: () => _printExam(context),
              icon: const Icon(Icons.print_rounded),
            ),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
          children: [
            _Appear(
              delayMs: 40,
              child: GlassContainer(
                borderRadius: 18,
                padding: const EdgeInsets.all(14),
                child: Column(
                  children: [
                    Row(
                      children: [
                        const Icon(
                          Icons.auto_awesome_rounded,
                          color: AppColors.primary,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          _title(type),
                          style: const TextStyle(fontWeight: FontWeight.w700),
                        ),
                        const Spacer(),
                        Text(
                          widget.generation.createdAt
                              .toLocal()
                              .toString()
                              .split('.')
                              .first,
                          style: const TextStyle(
                            fontSize: 12,
                            color: AppColors.textMuted,
                          ),
                        ),
                      ],
                    ),
                    if (_supportsModes) ...[
                      const SizedBox(height: 10),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: SegmentedButton<_ViewMode>(
                          selected: {_mode},
                          onSelectionChanged: (set) =>
                              setState(() => _mode = set.first),
                          segments: const [
                            ButtonSegment<_ViewMode>(
                              value: _ViewMode.student,
                              icon: Icon(Icons.school_outlined),
                              label: Text('Student'),
                            ),
                            ButtonSegment<_ViewMode>(
                              value: _ViewMode.teacher,
                              icon: Icon(Icons.badge_outlined),
                              label: Text('Teacher'),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            _Appear(delayMs: 120, child: _bodyForType(type)),
          ],
        ),
      ),
    );
  }

  Widget _bodyForType(String type) {
    switch (type) {
      case 'summary':
        return _SummaryCard(content: widget.generation.content);
      case 'concepts':
        return _ConceptsCard(content: widget.generation.content);
      case 'examples':
        return _ExamplesCard(content: widget.generation.content);
      case 'quiz':
        return _mode == _ViewMode.teacher
            ? _TeacherQuizCard(content: widget.generation.content)
            : _StudentQuizCard(content: widget.generation.content);
      case 'exam':
        return _ExamCard(
          content: widget.generation.content,
          teacherMode: _mode == _ViewMode.teacher,
        );
      default:
        return _RawJson(content: widget.generation.content);
    }
  }

  String _title(String t) => switch (t) {
    'summary' => 'Summary',
    'concepts' => 'Concepts',
    'examples' => 'Examples',
    'quiz' => 'Quiz',
    'exam' => 'Exam',
    _ => t.toUpperCase(),
  };

  Future<void> _exportCurrentAsPdf(BuildContext context) async {
    try {
      final pdf = pw.Document();
      final type = widget.generation.generationType;
      pdf.addPage(
        pw.MultiPage(
          margin: const pw.EdgeInsets.all(28),
          build: (_) =>
              _buildPdfBlocks(type, teacherMode: _mode == _ViewMode.teacher),
        ),
      );
      await Printing.layoutPdf(onLayout: (_) async => pdf.save());
    } catch (_) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Unable to export PDF.')));
    }
  }

  Future<void> _printExam(BuildContext context) async {
    try {
      final pdf = pw.Document();
      pdf.addPage(
        pw.MultiPage(
          margin: const pw.EdgeInsets.all(28),
          build: (_) =>
              _buildPdfBlocks('exam', teacherMode: _mode == _ViewMode.teacher),
        ),
      );
      await Printing.layoutPdf(onLayout: (_) async => pdf.save());
    } catch (_) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Unable to print exam now.')),
      );
    }
  }

  List<pw.Widget> _buildPdfBlocks(String type, {required bool teacherMode}) {
    final title = _title(type);
    final content = widget.generation.content;
    final isTeacherCopy = teacherMode && (type == "quiz" || type == "exam");
    final header = <pw.Widget>[
      if (type == 'exam')
        ..._buildExamHeaderPdf(content, isTeacherCopy: isTeacherCopy)
      else ...[
        pw.Text(
          '$title ${isTeacherCopy ? "(Teacher Copy)" : "(Student Copy)"}',
          style: pw.TextStyle(fontSize: 24, fontWeight: pw.FontWeight.bold),
        ),
        pw.SizedBox(height: 4),
        pw.Text(
          'Generated: ${widget.generation.createdAt.toLocal()}',
          style: const pw.TextStyle(fontSize: 10),
        ),
        pw.Divider(),
        pw.SizedBox(height: 8),
      ],
    ];

    if (type == 'exam') {
      return [...header, ..._buildExamPdf(content, teacherMode: teacherMode)];
    }
    if (type == 'quiz') {
      return [...header, ..._buildQuizPdf(content, teacherMode: teacherMode)];
    }
    if (type == 'summary') {
      final summary = content['summary']?.toString() ?? '';
      final points = (content['key_points'] as List?) ?? const [];
      return [
        ...header,
        if (summary.isNotEmpty)
          pw.Text(summary, style: const pw.TextStyle(lineSpacing: 3)),
        if (points.isNotEmpty) ...[
          pw.SizedBox(height: 12),
          pw.Text(
            'Key Points',
            style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
          ),
          pw.SizedBox(height: 6),
          ...points.map((p) => pw.Bullet(text: p.toString())),
        ],
      ];
    }
    return [...header, pw.Text(content.toString())];
  }

  List<pw.Widget> _buildQuizPdf(
    Map<String, dynamic> content, {
    required bool teacherMode,
  }) {
    final quiz = (content['quiz'] as List?) ?? const [];
    return quiz.asMap().entries.map((entry) {
      final q = entry.value as Map;
      final qType = q['type']?.toString().toLowerCase() ?? '';
      final options = (q['options'] as List?) ?? const [];
      final correct = q['correct_answer']?.toString() ?? '';
      final modelAnswer = q['model_answer']?.toString() ?? '';
      final explanation = q['explanation']?.toString() ?? '';
      return pw.Padding(
        padding: const pw.EdgeInsets.only(bottom: 12),
        child: pw.Column(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Text(
              'Q${entry.key + 1}. ${q['question'] ?? ''} (${q['marks'] ?? 0} marks)',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            if (options.isNotEmpty) ...[
              pw.SizedBox(height: 4),
              ..._pdfOptionRows(options),
            ],
            if (teacherMode) ...[
              pw.SizedBox(height: 4),
              pw.Text(
                qType == 'mcq'
                    ? 'Correct Answer: ${_normalizeOptionText(correct)}'
                    : 'Model Answer: ${modelAnswer.isNotEmpty ? modelAnswer : correct}',
                style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
              ),
              if (explanation.isNotEmpty) pw.Text('Explanation: $explanation'),
            ],
          ],
        ),
      );
    }).toList();
  }

  List<pw.Widget> _buildExamPdf(
    Map<String, dynamic> content, {
    required bool teacherMode,
  }) {
    final sections = (content['sections'] as List?) ?? const [];
    final instructions = (content['instructions'] as List?) ?? const [];
    final total = content['total_marks']?.toString() ?? '';
    final timeAllowed = content['time_allowed']?.toString() ?? '';
    return [
      if (total.isNotEmpty) pw.Text('Total Marks: $total'),
      if (timeAllowed.isNotEmpty) pw.Text('Time Allowed: $timeAllowed'),
      if (instructions.isNotEmpty) ...[
        pw.SizedBox(height: 8),
        pw.Text(
          'Instructions',
          style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
        ),
        pw.SizedBox(height: 4),
        ...instructions.map((i) => pw.Bullet(text: i.toString())),
      ],
      pw.SizedBox(height: 10),
      ...sections.map((sectionRaw) {
        final section = sectionRaw as Map;
        final questions = (section['questions'] as List?) ?? const [];
        return pw.Padding(
          padding: const pw.EdgeInsets.only(bottom: 10),
          child: pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.Text(
                section['section_name']?.toString() ?? 'Section',
                style: pw.TextStyle(
                  fontSize: 15,
                  fontWeight: pw.FontWeight.bold,
                ),
              ),
              pw.SizedBox(height: 6),
              ...questions.map((qRaw) {
                final q = qRaw as Map;
                final options = (q['options'] as List?) ?? const [];
                return pw.Padding(
                  padding: const pw.EdgeInsets.only(bottom: 8),
                  child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(
                        '${q['question_number'] ?? ''}. ${q['question_text'] ?? ''}',
                      ),
                      if (options.isNotEmpty) ...[
                        pw.SizedBox(height: 4),
                        ..._pdfOptionRows(options),
                      ],
                      if (teacherMode &&
                          (q['mark_scheme']?.toString() ?? '').isNotEmpty) ...[
                        pw.SizedBox(height: 4),
                        pw.Text(
                          'Mark Scheme: ${q['mark_scheme']}',
                          style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
                        ),
                      ],
                    ],
                  ),
                );
              }),
            ],
          ),
        );
      }),
    ];
  }

  List<pw.Widget> _pdfOptionRows(List options) {
    const labels = ['A', 'B', 'C', 'D', 'E', 'F'];
    return options.asMap().entries.map((entry) {
      final label = labels[entry.key % labels.length];
      final optionText = _normalizeOptionText(entry.value.toString());
      return pw.Padding(
        padding: const pw.EdgeInsets.only(bottom: 3),
        child: pw.Row(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Container(
              width: 11,
              height: 11,
              margin: const pw.EdgeInsets.only(top: 2),
              decoration: pw.BoxDecoration(border: pw.Border.all(width: 1)),
            ),
            pw.SizedBox(width: 6),
            pw.Expanded(child: pw.Text('$label. $optionText')),
          ],
        ),
      );
    }).toList();
  }

  List<pw.Widget> _buildExamHeaderPdf(
    Map<String, dynamic> content, {
    required bool isTeacherCopy,
  }) {
    final schoolName = (content['school_name']?.toString() ?? '').trim();
    final examTitle = (content['exam_title']?.toString() ?? 'Exam').trim();
    final classLevel = (content['class_level']?.toString() ?? '').trim();
    final subject = (content['subject']?.toString() ?? '').trim();
    final totalMarks = (content['total_marks']?.toString() ?? '').trim();
    final timeAllowed = (content['time_allowed']?.toString() ?? '').trim();

    final meta = <String>[];
    if (classLevel.isNotEmpty) meta.add('Class: $classLevel');
    if (subject.isNotEmpty) meta.add('Subject: $subject');
    if (totalMarks.isNotEmpty) meta.add('Total Marks: $totalMarks');
    if (timeAllowed.isNotEmpty) meta.add('Time: $timeAllowed');

    return [
      pw.Container(
        padding: const pw.EdgeInsets.fromLTRB(12, 10, 12, 10),
        decoration: pw.BoxDecoration(
          border: pw.Border.all(width: 1.1),
          borderRadius: pw.BorderRadius.circular(8),
        ),
        child: pw.Column(
          crossAxisAlignment: pw.CrossAxisAlignment.stretch,
          children: [
            if (schoolName.isNotEmpty)
              pw.Text(
                schoolName.toUpperCase(),
                textAlign: pw.TextAlign.center,
                style: pw.TextStyle(
                  fontSize: 14,
                  fontWeight: pw.FontWeight.bold,
                ),
              ),
            pw.SizedBox(height: schoolName.isNotEmpty ? 4 : 0),
            pw.Text(
              examTitle.toUpperCase(),
              textAlign: pw.TextAlign.center,
              style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold),
            ),
            pw.SizedBox(height: 6),
            pw.Text(
              isTeacherCopy ? 'TEACHER COPY' : 'STUDENT COPY',
              textAlign: pw.TextAlign.center,
              style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold),
            ),
            if (meta.isNotEmpty) ...[
              pw.SizedBox(height: 8),
              pw.Text(
                meta.join('   |   '),
                textAlign: pw.TextAlign.center,
                style: const pw.TextStyle(fontSize: 10),
              ),
            ],
          ],
        ),
      ),
      pw.SizedBox(height: 8),
      pw.Text(
        'Generated: ${widget.generation.createdAt.toLocal()}',
        style: const pw.TextStyle(fontSize: 9),
      ),
      pw.Divider(),
      pw.SizedBox(height: 8),
    ];
  }
}

String _normalizeOptionText(String text) {
  final trimmed = text.trim();
  final regex = RegExp(r'^[A-Fa-f][\)\.\:\-]\s*');
  return trimmed.replaceFirst(regex, '');
}

class _SummaryCard extends StatelessWidget {
  const _SummaryCard({required this.content});
  final Map<String, dynamic> content;
  @override
  Widget build(BuildContext context) {
    final summary = content['summary']?.toString() ?? content.toString();
    final points =
        (content['key_points'] as List?)?.map((e) => e.toString()).toList() ??
        const <String>[];
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(summary, style: const TextStyle(height: 1.45)),
          if (points.isNotEmpty) ...[
            const SizedBox(height: 10),
            const Text(
              'Key Points',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            ...points.map((p) => Text('- $p')),
          ],
        ],
      ),
    );
  }
}

class _ConceptsCard extends StatelessWidget {
  const _ConceptsCard({required this.content});
  final Map<String, dynamic> content;
  @override
  Widget build(BuildContext context) {
    final concepts = (content['concepts'] as List?) ?? const [];
    if (concepts.isEmpty) return _RawJson(content: content);
    return Column(
      children: concepts.map((raw) {
        final m = raw as Map;
        final related = (m['related_to'] as List?) ?? const [];
        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: GlassContainer(
            borderRadius: 16,
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  m['name']?.toString() ?? 'Concept',
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 6),
                Text(m['explanation']?.toString() ?? ''),
                if (related.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: related
                        .map((r) => Chip(label: Text(r.toString())))
                        .toList(),
                  ),
                ],
              ],
            ),
          ),
        );
      }).toList(),
    );
  }
}

class _ExamplesCard extends StatelessWidget {
  const _ExamplesCard({required this.content});
  final Map<String, dynamic> content;
  @override
  Widget build(BuildContext context) {
    final examples = (content['examples'] as List?) ?? const [];
    if (examples.isEmpty) return _RawJson(content: content);
    return Column(
      children: examples.map((raw) {
        final m = raw as Map;
        final steps = (m['solution_steps'] as List?) ?? const [];
        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: GlassContainer(
            borderRadius: 16,
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Problem: ${m['problem'] ?? ''}',
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 6),
                ...steps.asMap().entries.map(
                  (e) => Text('${e.key + 1}. ${e.value}'),
                ),
                if ((m['answer']?.toString() ?? '').isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text('Answer: ${m['answer']}'),
                ],
              ],
            ),
          ),
        );
      }).toList(),
    );
  }
}

class _StudentQuizCard extends StatefulWidget {
  const _StudentQuizCard({required this.content});
  final Map<String, dynamic> content;
  @override
  State<_StudentQuizCard> createState() => _StudentQuizCardState();
}

class _StudentQuizCardState extends State<_StudentQuizCard> {
  final Map<int, String> answers = {};
  int index = 0;
  int left = 45;
  bool submitted = false;
  Timer? timer;
  List get quiz => (widget.content['quiz'] as List?) ?? const [];

  @override
  void initState() {
    super.initState();
    _tick();
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  void _tick() {
    timer?.cancel();
    left = 45;
    timer = Timer.periodic(const Duration(seconds: 1), (t) {
      if (!mounted || submitted) return t.cancel();
      if (left <= 1) {
        t.cancel();
        _next();
      } else {
        setState(() => left -= 1);
      }
    });
  }

  void _next() {
    if (index < quiz.length - 1) {
      setState(() => index += 1);
      _tick();
    } else {
      setState(() => submitted = true);
      timer?.cancel();
    }
  }

  int _score() {
    var s = 0;
    for (var i = 0; i < quiz.length; i++) {
      final q = quiz[i] as Map;
      if (answers[i] == q['correct_answer']?.toString()) {
        s += (q['marks'] as num?)?.toInt() ?? 1;
      }
    }
    return s;
  }

  int _total() {
    var s = 0;
    for (final q in quiz) {
      s += ((q as Map)['marks'] as num?)?.toInt() ?? 1;
    }
    return math.max(s, 1);
  }

  @override
  Widget build(BuildContext context) {
    if (quiz.isEmpty) return _RawJson(content: widget.content);
    if (submitted) {
      final score = _score();
      final total = _total();
      final pass = score >= (total * 0.6).round();
      return GlassContainer(
        borderRadius: 18,
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              pass ? 'Passed: $score/$total' : 'Failed: $score/$total',
              style: TextStyle(
                fontWeight: FontWeight.w700,
                color: pass ? Colors.greenAccent : Colors.redAccent,
              ),
            ),
            const SizedBox(height: 8),
            ...quiz.asMap().entries.map((e) {
              final q = e.value as Map;
              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                  'Q${e.key + 1}: correct = ${q['correct_answer'] ?? q['model_answer'] ?? ''}',
                ),
              );
            }),
          ],
        ),
      );
    }

    final q = quiz[index] as Map;
    final options =
        (q['options'] as List?)?.map((e) => e.toString()).toList() ??
        const <String>[];
    return Column(
      children: [
        GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(14),
          child: Row(
            children: [
              Text('Question ${index + 1}/${quiz.length}'),
              const Spacer(),
              Text('$left s'),
            ],
          ),
        ),
        const SizedBox(height: 10),
        GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                q['question']?.toString() ?? '',
                style: const TextStyle(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 8),
              ...options.asMap().entries.map((entry) {
                final label = String.fromCharCode(65 + entry.key);
                final clean = _normalizeOptionText(entry.value);
                return RadioListTile<String>(
                  value: entry.value,
                  groupValue: answers[index],
                  onChanged: (_) =>
                      setState(() => answers[index] = entry.value),
                  title: Text('$label. $clean'),
                );
              }),
            ],
          ),
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _next,
            child: Text(index == quiz.length - 1 ? 'Submit' : 'Next'),
          ),
        ),
      ],
    );
  }
}

class _TeacherQuizCard extends StatelessWidget {
  const _TeacherQuizCard({required this.content});
  final Map<String, dynamic> content;

  @override
  Widget build(BuildContext context) {
    final quiz = (content['quiz'] as List?) ?? const [];
    if (quiz.isEmpty) return _RawJson(content: content);
    return Column(
      children: quiz.asMap().entries.map((entry) {
        final q = entry.value as Map;
        final options = (q['options'] as List?) ?? const [];
        final qType = q['type']?.toString().toLowerCase() ?? '';
        final correct = q['correct_answer']?.toString() ?? '';
        final modelAnswer = q['model_answer']?.toString() ?? '';
        final explanation = q['explanation']?.toString() ?? '';
        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: GlassContainer(
            borderRadius: 16,
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Q${entry.key + 1}. ${q['question'] ?? ''} (${q['marks'] ?? 0} marks)',
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                if (options.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  ...options.asMap().entries.map((opt) {
                    final label = String.fromCharCode(65 + opt.key);
                    return Text(
                      '$label. ${_normalizeOptionText(opt.value.toString())}',
                    );
                  }),
                ],
                const SizedBox(height: 8),
                Text(
                  qType == 'mcq'
                      ? 'Correct Answer: ${_normalizeOptionText(correct)}'
                      : 'Model Answer: ${modelAnswer.isNotEmpty ? modelAnswer : correct}',
                  style: const TextStyle(
                    fontWeight: FontWeight.w700,
                    color: Colors.greenAccent,
                  ),
                ),
                if (explanation.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text(
                    'Explanation: $explanation',
                    style: const TextStyle(color: AppColors.textMuted),
                  ),
                ],
              ],
            ),
          ),
        );
      }).toList(),
    );
  }
}

class _ExamCard extends StatefulWidget {
  const _ExamCard({required this.content, required this.teacherMode});
  final Map<String, dynamic> content;
  final bool teacherMode;

  @override
  State<_ExamCard> createState() => _ExamCardState();
}

class _ExamCardState extends State<_ExamCard> {
  final Set<int> _expanded = <int>{};

  @override
  Widget build(BuildContext context) {
    final content = widget.content;
    final sections = (content['sections'] as List?) ?? const [];
    final schoolName = (content['school_name']?.toString() ?? '').trim();
    final examTitle = (content['exam_title']?.toString() ?? 'Exam').trim();
    final subject = (content['subject']?.toString() ?? '').trim();
    final classLevel = (content['class_level']?.toString() ?? '').trim();
    return Column(
      children: [
        GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (schoolName.isNotEmpty)
                Center(
                  child: Text(
                    schoolName.toUpperCase(),
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.8,
                    ),
                  ),
                ),
              if (schoolName.isNotEmpty) const SizedBox(height: 4),
              Center(
                child: Text(
                  examTitle.toUpperCase(),
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 18,
                  ),
                ),
              ),
              if (subject.isNotEmpty || classLevel.isNotEmpty) ...[
                const SizedBox(height: 6),
                Center(
                  child: Text(
                    [
                      if (classLevel.isNotEmpty) 'Class: $classLevel',
                      if (subject.isNotEmpty) 'Subject: $subject',
                    ].join('   |   '),
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: AppColors.textMuted),
                  ),
                ),
              ],
              const SizedBox(height: 6),
              if ((content['total_marks']?.toString() ?? '').isNotEmpty)
                Text('Total marks: ${content['total_marks']}'),
              if ((content['time_allowed']?.toString() ?? '').isNotEmpty)
                Text('Time allowed: ${content['time_allowed']}'),
              Text(
                widget.teacherMode ? 'Teacher Copy' : 'Student Copy',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 10),
        ...sections.asMap().entries.map((entry) {
          final sectionIndex = entry.key;
          final raw = entry.value;
          final s = raw as Map;
          final questions = (s['questions'] as List?) ?? const [];
          return Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: GlassContainer(
              borderRadius: 16,
              padding: const EdgeInsets.all(6),
              child: Theme(
                data: Theme.of(
                  context,
                ).copyWith(dividerColor: Colors.transparent),
                child: ExpansionTile(
                  onExpansionChanged: (open) {
                    setState(() {
                      if (open) {
                        _expanded.add(sectionIndex);
                      } else {
                        _expanded.remove(sectionIndex);
                      }
                    });
                  },
                  initiallyExpanded: _expanded.contains(sectionIndex),
                  tilePadding: const EdgeInsets.symmetric(horizontal: 10),
                  childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 12),
                  title: Text(
                    s['section_name']?.toString() ?? 'Section',
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  subtitle: Text('${questions.length} questions'),
                  children: [
                    ...questions.map((qRaw) {
                      final q = qRaw as Map;
                      final options = (q['options'] as List?) ?? const [];
                      return AnimatedContainer(
                        duration: const Duration(milliseconds: 220),
                        curve: Curves.easeOutCubic,
                        margin: const EdgeInsets.only(bottom: 10),
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.02),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: AppColors.glassBorder),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              '${q['question_number'] ?? ''}. ${q['question_text'] ?? ''}',
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            if (options.isNotEmpty) ...[
                              const SizedBox(height: 6),
                              ...options.asMap().entries.map(
                                (entry) => _OptionChoiceTile(
                                  label: String.fromCharCode(65 + entry.key),
                                  text: _normalizeOptionText(
                                    entry.value.toString(),
                                  ),
                                ),
                              ),
                            ],
                            if (widget.teacherMode &&
                                (q['mark_scheme']?.toString() ?? '')
                                    .isNotEmpty) ...[
                              const SizedBox(height: 6),
                              Text(
                                'Mark Scheme: ${q['mark_scheme']}',
                                style: const TextStyle(
                                  color: Colors.greenAccent,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ],
                          ],
                        ),
                      );
                    }),
                  ],
                ),
              ),
            ),
          );
        }),
      ],
    );
  }
}

class _OptionChoiceTile extends StatelessWidget {
  const _OptionChoiceTile({required this.label, required this.text});

  final String label;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 18,
            height: 18,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              border: Border.all(color: AppColors.glassBorder),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              label,
              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: const TextStyle(height: 1.25))),
        ],
      ),
    );
  }
}

class _RawJson extends StatelessWidget {
  const _RawJson({required this.content});
  final Map<String, dynamic> content;
  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: SelectableText(content.toString()),
    );
  }
}

class _Appear extends StatefulWidget {
  const _Appear({required this.child, required this.delayMs});
  final Widget child;
  final int delayMs;
  @override
  State<_Appear> createState() => _AppearState();
}

class _AppearState extends State<_Appear> {
  bool visible = false;
  @override
  void initState() {
    super.initState();
    Future<void>.delayed(Duration(milliseconds: widget.delayMs), () {
      if (mounted) setState(() => visible = true);
    });
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedOpacity(
      opacity: visible ? 1 : 0,
      duration: const Duration(milliseconds: 250),
      child: AnimatedSlide(
        offset: visible ? Offset.zero : const Offset(0, .04),
        duration: const Duration(milliseconds: 280),
        child: widget.child,
      ),
    );
  }
}
