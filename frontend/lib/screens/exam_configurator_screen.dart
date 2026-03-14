import 'dart:async';

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'generation_viewer_screen.dart';
import 'chat_with_notes_screen.dart';
import 'jobs_screen.dart';
import 'subscriptions_screen.dart';

class ExamConfiguratorScreen extends StatefulWidget {
  const ExamConfiguratorScreen({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onSessionUpdated,
    required this.onSessionInvalid,
    this.initialDocumentIds = const [],
    this.initialCbcNoteIds = const [],
    this.initialTopic,
  });

  final ApiClient apiClient;
  final Session session;
  final ValueChanged<Session> onSessionUpdated;
  final VoidCallback onSessionInvalid;
  final List<String> initialDocumentIds;
  final List<String> initialCbcNoteIds;
  final String? initialTopic;

  @override
  State<ExamConfiguratorScreen> createState() => _ExamConfiguratorScreenState();
}

class _ExamConfiguratorScreenState extends State<ExamConfiguratorScreen> {
  final TextEditingController _topicController = TextEditingController();
  final TextEditingController _instructionsController = TextEditingController();
  final FocusNode _instructionsFocusNode = FocusNode();
  final GlobalKey _instructionsEditorKey = GlobalKey();
  final TextEditingController _marksController = TextEditingController(
    text: '100',
  );
  final TextEditingController _questionsController = TextEditingController(
    text: '10',
  );

  final Set<String> _selectedDocumentIds = {};
  final Set<String> _selectedCbcNoteIds = {};
  final List<DocumentMetadata> _documents = [];
  final List<String> _generationTypes = const [
    'exam',
    'quiz',
    'summary',
    'concepts',
    'examples',
    'chat',
  ];

  String _generationType = 'exam';
  String _difficulty = 'medium';
  String _examSectionMode = 'mixed';
  String _selectedLevel = 'F4';
  String _selectedPaper = 'PP1';
  String _selectedSubject = 'Biology';
  bool _useBlueprint = true;
  bool _isLoadingDocuments = true;
  bool _isGenerating = false;
  bool _isPollingJob = false;
  String? _error;
  GenerationResponse? _latestGeneration;
  GenerationJobResponse? _latestQueuedJob;
  JobStatusResponse? _activeJobStatus;
  Timer? _jobPollTimer;
  bool _templatesExpanded = false;
  final Set<String> _selectedTemplateIds = <String>{};
  final Map<String, String> _templateInsertedBlocks = <String, String>{};
  static const List<String> _levelOptions = [
    'F1',
    'F2',
    'F3',
    'F4',
    'G7',
    'G8',
    'G9',
  ];
  static const List<String> _paperOptions = ['PP1', 'PP2', 'PP3'];
  static const List<String> _formSubjects = [
    'Biology',
    'Chemistry',
    'Physics',
    'English',
    'History',
    'Geography',
    'Business Studies',
    'CRE',
    'Agriculture',
    'Computer Studies',
  ];
  static const List<String> _cbcSubjects = [
    'Integrated Science',
    'Mathematics',
    'Business Studies',
    'Agriculture',
    'Computer Science',
    'Life Skills',
    'Performing Arts',
  ];
  static const List<_PromptTemplate> _promptTemplates = [
    _PromptTemplate(
      id: 'single_section_no_mcq_essay',
      title: 'Single Section (Question + Marks)',
      subtitle: 'Structured-only paper with professional formatting.',
      body:
          'Create ONE section only. Each item must be written as "Question ... (X marks)". '
          'Do not include multiple-choice or essay questions. Use only structured/short and medium response items. '
          'Ensure each question is clearly stated using verbs like State, Explain, Identify, Describe, and Calculate. '
          'Distribute marks realistically based on cognitive load and expected answer length. '
          'Each question mark should be minimum 1 and maximum 4. '
          'Use a professional question paper layout with clear numbering, question text, and marks.',
      recommendedFor: {'exam'},
    ),
    _PromptTemplate(
      id: 'senior_school_exam_tone',
      title: 'Senior School Exam Tone',
      subtitle: 'KCSE-style clarity and rigor.',
      body:
          'Write as a formal senior school examination paper. '
          'Questions must be precise, syllabus-aligned, and free of ambiguity. '
          'Prioritize command words such as State, Explain, Identify, Describe, Distinguish, and Calculate. '
          'Ensure progression from basic understanding to application and analysis.',
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'cbc_competency_focus',
      title: 'CBC Competency Focus',
      subtitle: 'Competency and application orientation.',
      body:
          'Frame tasks to assess competencies: knowledge application, communication, critical thinking, and problem solving. '
          'Use contextualized prompts and avoid purely memorization-heavy items unless required by the provided material.',
      recommendedFor: {'exam', 'quiz', 'summary', 'concepts'},
    ),
    _PromptTemplate(
      id: 'institution_header_custom',
      title: 'School + Term Header',
      subtitle: 'School name and term.',
      body:
          'Use the school name "{{school_name}}" and term "{{exam_title}}" in the exam header.',
      requiresSchoolName: true,
      requiresExamTitle: true,
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'marking_realism',
      title: 'Marking Realism Guard',
      subtitle: 'Align cognitive load to marks.',
      body:
          'Make mark allocation realistic: 1-2 marks for factual recall, 3-5 for short explanations, '
          '6+ for multi-step reasoning. Avoid over-weighting simple recall tasks. '
          'Ensure total marks exactly match requested marks.',
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'senior_school_structured_1_to_4',
      title: 'Senior School Structured (1-4 Marks)',
      subtitle: 'Professional numbered paper, structured only.',
      body:
          'Create ONE section only. Each item must be written as "Question ... (X marks)". '
          'Do not include multiple-choice or essay questions. Use only structured/short and medium response items. '
          'Ensure each question is clearly stated using verbs like State, Explain, Identify, Describe, and Calculate. '
          'Distribute marks realistically based on cognitive load and expected answer length. '
          'Use a minimum of 1 mark and maximum of 4 marks per question. '
          'Output a professional question paper format with Number, Question, and (Marks).',
      recommendedFor: {'exam'},
    ),
    _PromptTemplate(
      id: 'directive_verbs',
      title: 'Directive Verb Quality',
      subtitle: 'Exam command words only.',
      body:
          'Phrase each question with explicit exam directive verbs (State, Define, Identify, Explain, Compare, Evaluate). '
          'Avoid vague wording and ambiguous prompts.',
      recommendedFor: {'exam', 'quiz', 'summary'},
    ),
    _PromptTemplate(
      id: 'difficulty_progression',
      title: 'Difficulty Progression',
      subtitle: 'Easy to hard sequencing.',
      body:
          'Sequence questions progressively from foundational to advanced. '
          'First 30% should test core recall and understanding, middle 40% application, last 30% deeper reasoning.',
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'strict_curriculum_anchor',
      title: 'Curriculum Anchoring',
      subtitle: 'No out-of-scope content.',
      body:
          'Base all questions strictly on provided materials only. '
          'Do not introduce external or off-syllabus content.',
      recommendedFor: {'exam', 'quiz', 'summary', 'concepts', 'examples'},
    ),
    _PromptTemplate(
      id: 'question_numbering_layout',
      title: 'Numbered Layout Guard',
      subtitle: 'Strict Number, Question, (Marks) pattern.',
      body:
          'Output questions in a clean numbered sequence only. '
          'Each line must follow: Number. Question text (X marks). '
          'Do not merge questions, and do not omit marks from any item.',
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'concise_mark_scheme',
      title: 'Concise Mark Scheme',
      subtitle: 'Actionable and clear points.',
      body:
          'Provide a concise marking scheme for each question with key points and mark split. '
          'Marking notes must be practical for a teacher to grade quickly.',
      recommendedFor: {'exam'},
    ),
  ];
  bool _appliedInitialSelection = false;

  @override
  void initState() {
    super.initState();
    final initialTopic = (widget.initialTopic ?? '').trim();
    if (initialTopic.isNotEmpty) {
      _topicController.text = initialTopic;
    }
    _selectedCbcNoteIds.addAll(widget.initialCbcNoteIds);
    _loadDocuments();
  }

  @override
  void didUpdateWidget(covariant ExamConfiguratorScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadDocuments();
    }
  }

  @override
  void dispose() {
    _jobPollTimer?.cancel();
    _topicController.dispose();
    _instructionsController.dispose();
    _instructionsFocusNode.dispose();
    _marksController.dispose();
    _questionsController.dispose();
    super.dispose();
  }

  Future<void> _loadDocuments() async {
    setState(() {
      _isLoadingDocuments = true;
      _error = null;
    });
    try {
      final docs = await _runWithAuthRetry(
        (token) => widget.apiClient.listDocuments(token),
      );
      if (!mounted) return;
      setState(() {
        _documents
          ..clear()
          ..addAll(docs);
        if (!_appliedInitialSelection && widget.initialDocumentIds.isNotEmpty) {
          final availableIds = _documents.map((d) => d.id).toSet();
          final matched = widget.initialDocumentIds
              .where((id) => availableIds.contains(id))
              .toSet();
          if (matched.isNotEmpty) {
            _selectedDocumentIds
              ..clear()
              ..addAll(matched);
          }
          _appliedInitialSelection = true;
        }
        if (_documents.isNotEmpty && _selectedDocumentIds.isEmpty) {
          _selectedDocumentIds.add(_documents.first.id);
        }
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Failed to load documents.');
    } finally {
      if (mounted) {
        setState(() => _isLoadingDocuments = false);
      }
    }
  }

  Future<void> _generate() async {
    if (_selectedDocumentIds.isEmpty && _selectedCbcNoteIds.isEmpty) {
      setState(() => _error = 'Select at least one document or shared note.');
      return;
    }


    if (_generationType == 'chat') {
      setState(() => _error = null);
      _openChatWithNotes();
      return;
    }    final proceed = await _confirmPromptReview();
    if (!proceed) return;

    setState(() {
      _isGenerating = true;
      _error = null;
    });

    try {
      if (_generationType == 'exam') {
        final examValidation = _validateExamBlueprintInputs();
        if (examValidation != null) {
          setState(() => _error = examValidation);
          return;
        }
      }
      final mergedInstructions = _buildRequestInstructions();
      final computedTopic = _effectiveTopic();
      final request = GenerationRequest(
        documentIds: _selectedDocumentIds.toList(),
        cbcNoteIds: _selectedCbcNoteIds.toList(),
        generationType: _generationType,
        topic: computedTopic.trim().isEmpty ? null : computedTopic.trim(),
        difficulty: _difficulty,
        marks: _generationType == 'exam'
            ? int.tryParse(_marksController.text.trim())
            : null,
        numQuestions:
            (_generationType == 'quiz' || _generationType == 'examples')
            ? int.tryParse(_questionsController.text.trim())
            : null,
        questionTypes: _generationType == 'exam'
            ? _questionTypesForExam()
            : _generationType == 'quiz'
            ? const ['mcq', 'structured']
            : null,
        additionalInstructions: mergedInstructions,
      );

      final queued = await _runWithAuthRetry(
        (token) =>
            widget.apiClient.generate(accessToken: token, request: request),
      );
      if (!mounted) return;
      setState(() {
        _latestQueuedJob = queued;
        _activeJobStatus = null;
      });
      _startJobPolling(queued.jobId);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
      if (e.statusCode == 402) {
        _showSubscriptionPrompt(e.message);
      }
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Generation failed. Please retry.');
    } finally {
      if (mounted) {
        setState(() => _isGenerating = false);
      }
    }
  }

  String? _buildRequestInstructions() {
    final base = _instructionsController.text.trim();
    final autoHints = <String>[];
    if (_generationType == 'exam' && _useBlueprint) {
      autoHints.add(
        'Exam blueprint target: ${_levelLabel(_selectedLevel)} $_selectedSubject $_selectedPaper.',
      );
      if (_selectedPaper == 'PP1') {
        autoHints.add(
          'Generate a theory paper (Paper 1) with clear, answerable exam questions and realistic mark allocation.',
        );
      } else if (_selectedPaper == 'PP2') {
        if (_isPracticalSubject(_selectedSubject)) {
          autoHints.add(
            'Generate Paper 2 in application/practical-leaning style: structured tasks, data interpretation, and stepwise marking points.',
          );
        } else {
          autoHints.add(
            'Generate Paper 2 in theory/application style with sections and choice where appropriate.',
          );
        }
      } else if (_selectedPaper == 'PP3') {
        autoHints.add(
          'Generate Paper 3 practical: task-based items, procedure/observation/calculation prompts, and explicit step-by-step mark scheme.',
        );
      }
    }
    if (_generationType == 'exam' && _examSectionMode == 'structured_only') {
      autoHints.add(
        'Question and marks only. Output one numbered section. '
        'Every item must be an answerable exam question using an exam command verb '
        '(State, Explain, Identify, Describe, Calculate, Compare). '
        'Do not output topic statements, options, or essay-style prompts.',
      );
    }
    if (_generationType == 'quiz') {
      autoHints.add(
        'Every quiz item must be a real answerable question, not a statement or note. '
        'Each item must include marks and clear question wording.',
      );
    }
    final merged = [
      if (base.isNotEmpty) base,
      ...autoHints,
    ].join('\n\n').trim();
    return merged.isEmpty ? null : merged;
  }

  void _startJobPolling(String jobId) {
    _jobPollTimer?.cancel();
    _pollJobStatus(jobId);
    _jobPollTimer = Timer.periodic(
      const Duration(seconds: 3),
      (_) => _pollJobStatus(jobId),
    );
  }

  Future<void> _pollJobStatus(String jobId) async {
    if (_isPollingJob) return;
    _isPollingJob = true;
    try {
      final status = await _runWithAuthRetry(
        (token) =>
            widget.apiClient.getJobStatus(accessToken: token, jobId: jobId),
      );
      if (!mounted) return;
      setState(() => _activeJobStatus = status);
      if (status.isTerminal) {
        _jobPollTimer?.cancel();
        if (status.status == 'completed' && status.resultReference != null) {
          final generation = await _runWithAuthRetry(
            (token) => widget.apiClient.getGeneration(
              accessToken: token,
              generationId: status.resultReference!,
            ),
          );
          if (!mounted) return;
          setState(() => _latestGeneration = generation);
        } else if (status.status == 'failed' && mounted) {
          setState(() {
            _error = status.error ?? 'Generation failed. Please retry.';
          });
        }
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to fetch generation job status.');
    } finally {
      _isPollingJob = false;
    }
  }

  String _jobStatusLabel() {
    final status = _activeJobStatus?.status ?? _latestQueuedJob?.status;
    switch (status) {
      case 'queued':
        return 'Queued';
      case 'processing':
        return 'Generating';
      case 'retrying':
        return 'Retrying';
      case 'completed':
        return 'Completed';
      case 'failed':
        return 'Failed';
      default:
        return 'Idle';
    }
  }

  Color _jobStatusColor() {
    final status = _activeJobStatus?.status ?? _latestQueuedJob?.status;
    switch (status) {
      case 'completed':
        return Colors.greenAccent;
      case 'failed':
        return Colors.redAccent;
      case 'processing':
      case 'retrying':
        return AppColors.accent;
      case 'queued':
        return Colors.amberAccent;
      default:
        return AppColors.textMuted;
    }
  }

  String _documentRetentionLabel(DocumentMetadata doc) {
    final expiresAt = doc.retentionExpiresAt;
    if (expiresAt == null) {
      final days = doc.retentionDays;
      if (days != null && days > 0) {
        return 'Expires after $days day(s) from upload';
      }
      return 'Expiry follows your current retention policy';
    }
    final diff = expiresAt.difference(DateTime.now());
    if (diff.inSeconds <= 0) return 'Expired or expiring now';
    if (diff.inHours < 24) return 'Expires in about ${diff.inHours} hour(s)';
    return 'Expires in about ${diff.inDays} day(s)';
  }

  void _showSubscriptionPrompt(String message) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Upgrade Required'),
        content: Text(
          '$message\n\nYou have reached your current generation limit. Choose a credit pack to continue.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Later'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => SubscriptionsScreen(
                    apiClient: widget.apiClient,
                    session: widget.session,
                    onSessionUpdated: widget.onSessionUpdated,
                    onSessionInvalid: widget.onSessionInvalid,
                  ),
                ),
              );
            },
            child: const Text('View Plans'),
          ),
        ],
      ),
    );
  }

  void _openJobsScreen() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => JobsScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onSessionInvalid,
        ),
      ),
    );
  }


  void _openChatWithNotes() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ChatWithNotesScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onSessionInvalid,
          documentIds: _selectedDocumentIds.toList(),
          cbcNoteIds: _selectedCbcNoteIds.toList(),
        ),
      ),
    );
  }
  void _openLatestGeneration() {
    final latest = _latestGeneration;
    if (latest == null) return;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => GenerationViewerScreen(
              generation: latest,
              apiClient: widget.apiClient,
              session: widget.session,
              onSessionUpdated: widget.onSessionUpdated,
              onSessionInvalid: widget.onSessionInvalid,
            ),
      ),
    );
  }

  List<_PromptTemplate> _visibleTemplates() {
    final visible = _promptTemplates
        .where(
          (t) =>
              t.id == 'institution_header_custom' &&
              t.recommendedFor.contains(_generationType),
        )
        .toList();
    visible.sort((a, b) => a.title.compareTo(b.title));
    return visible;
  }

  Future<void> _toggleTemplateSelection(_PromptTemplate template) async {
    if (_selectedTemplateIds.contains(template.id)) {
      _removeTemplateSnippet(template.id);
      setState(() {
        _selectedTemplateIds.remove(template.id);
        _templateInsertedBlocks.remove(template.id);
      });
      _showTemplateToast('Template removed from instructions.');
      return;
    }
    final rendered = await _renderTemplate(template);
    if (rendered == null) return;
    final insertedBlock = _appendInstructionSnippet(template.id, rendered);
    setState(() {
      _selectedTemplateIds.add(template.id);
      _templateInsertedBlocks[template.id] = insertedBlock;
    });
    _showTemplateToast('Template added to instructions.');
  }

  Future<String?> _renderTemplate(_PromptTemplate template) async {
    var text = template.body;
    if (!template.requiresSchoolName && !template.requiresExamTitle) {
      return text;
    }

    final schoolController = TextEditingController();
    final examTitleController = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Template Details'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (template.requiresSchoolName)
              TextField(
                controller: schoolController,
                decoration: const InputDecoration(
                  labelText: 'School name',
                  hintText: 'e.g. Sunrise Academy',
                ),
              ),
            if (template.requiresExamTitle) ...[
              if (template.requiresSchoolName) const SizedBox(height: 10),
              TextField(
                controller: examTitleController,
                decoration: const InputDecoration(
                  labelText: 'Term',
                  hintText: 'e.g. Mid Term or End Term',
                ),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Apply'),
          ),
        ],
      ),
    );

    if (ok != true) return null;
    if (template.requiresSchoolName) {
      final school = schoolController.text.trim();
      if (school.isEmpty) return null;
      text = text.replaceAll('{{school_name}}', school);
    }
    if (template.requiresExamTitle) {
      final examTitle = examTitleController.text.trim();
      if (examTitle.isEmpty) return null;
      text = text.replaceAll('{{exam_title}}', examTitle);
    }
    return text;
  }

  String _appendInstructionSnippet(String _, String snippet) {
    final current = _instructionsController.text.trim();
    final block = snippet.trim();
    final next = current.isEmpty ? block : '$current\n\n$block';
    _instructionsController.text = next;
    _instructionsController.selection = TextSelection.fromPosition(
      TextPosition(offset: _instructionsController.text.length),
    );
    _instructionsFocusNode.requestFocus();
    _scrollToInstructionsEditor();
    return block;
  }

  List<String> _questionTypesForExam() {
    if (_selectedPaper == 'PP3') {
      return const ['practical'];
    }
    if (_selectedPaper == 'PP2' && _isPracticalSubject(_selectedSubject)) {
      return const ['practical', 'structured'];
    }
    switch (_examSectionMode) {
      case 'structured_only':
        return const ['structured'];
      case 'mcq_only':
        return const ['mcq'];
      case 'essay_only':
        return const ['essay'];
      default:
        return const ['mcq', 'structured', 'essay'];
    }
  }

  bool _isCbcLevel(String level) => level.startsWith('G');

  bool _isPracticalSubject(String subject) {
    final s = subject.toLowerCase();
    return s.contains('biology') ||
        s.contains('chemistry') ||
        s.contains('physics') ||
        s.contains('agriculture') ||
        s.contains('computer') ||
        s.contains('integrated science') ||
        s.contains('performing arts');
  }

  List<String> _subjectsForLevel(String level) {
    return _isCbcLevel(level) ? _cbcSubjects : _formSubjects;
  }

  String _levelLabel(String level) {
    if (level.startsWith('F')) {
      return 'Form ${level.substring(1)}';
    }
    if (level.startsWith('G')) {
      return 'Grade ${level.substring(1)}';
    }
    return level;
  }

  String _effectiveTopic() {
    final manual = _topicController.text.trim();
    if (manual.isNotEmpty) return manual;
    return '${_levelLabel(_selectedLevel)} $_selectedSubject $_selectedPaper';
  }

  String? _validateExamBlueprintInputs() {
    final marks = int.tryParse(_marksController.text.trim());
    if (marks == null || marks <= 0) {
      return 'Enter a valid total marks value for exam generation.';
    }
    if (_useBlueprint &&
        _selectedPaper == 'PP3' &&
        !_isPracticalSubject(_selectedSubject)) {
      return 'PP3 is practical. Select a practical subject or switch to PP1/PP2.';
    }
    return null;
  }

  void _onBlueprintLevelSelected(String level) {
    final subjects = _subjectsForLevel(level);
    var nextSubject = _selectedSubject;
    var nextPaper = _selectedPaper;
    if (!subjects.contains(nextSubject)) {
      nextSubject = subjects.first;
    }
    if (_isCbcLevel(level) && nextPaper == 'PP3') {
      nextPaper = 'PP2';
    }
    setState(() {
      _selectedLevel = level;
      _selectedSubject = nextSubject;
      _selectedPaper = nextPaper;
    });
  }

  void _onBlueprintSubjectSelected(String subject) {
    setState(() {
      _selectedSubject = subject;
      if (_selectedPaper == 'PP3' && !_isPracticalSubject(subject)) {
        _selectedPaper = 'PP2';
      }
    });
  }

  void _onBlueprintPaperSelected(String paper) {
    var nextPaper = paper;
    if (paper == 'PP3' && !_isPracticalSubject(_selectedSubject)) {
      nextPaper = 'PP2';
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'PP3 is for practical subjects. Switched to PP2 for this subject.',
          ),
          duration: Duration(milliseconds: 1400),
        ),
      );
    }
    setState(() => _selectedPaper = nextPaper);
  }

  String _paperGuideText() {
    if (_selectedPaper == 'PP1') {
      return 'PP1: theory paper with short and extended response items.';
    }
    if (_selectedPaper == 'PP2') {
      return _isPracticalSubject(_selectedSubject)
          ? 'PP2: application/practical-leaning tasks with stepwise marking points.'
          : 'PP2: theory/application paper with structured sections.';
    }
    return 'PP3: practical task paper with procedures, observations, and calculations.';
  }

  Future<bool> _confirmPromptReview() async {
    final instructions = _instructionsController.text.trim();
    final preview = instructions.isEmpty
        ? 'No additional instructions set.'
        : instructions.length > 220
        ? '${instructions.substring(0, 220)}...'
        : instructions;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Review Prompt Before Generate'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Please confirm your prompt details before generation.'),
            const SizedBox(height: 10),
            Text(
              preview,
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Edit Prompt'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Generate Now'),
          ),
        ],
      ),
    );
    return ok == true;
  }

  void _removeTemplateSnippet(String templateId) {
    final block = _templateInsertedBlocks[templateId];
    if (block == null || block.isEmpty) return;
    var text = _instructionsController.text;
    if (text.isEmpty) return;
    text = text.replaceAll('\n\n$block', '');
    text = text.replaceAll('$block\n\n', '');
    text = text.replaceAll(block, '');
    text = text.replaceAll(RegExp(r'\n{3,}'), '\n\n').trim();
    _instructionsController.text = text;
    _instructionsController.selection = TextSelection.fromPosition(
      TextPosition(offset: _instructionsController.text.length),
    );
    _scrollToInstructionsEditor();
  }

  void _clearSelectedTemplates() {
    if (_selectedTemplateIds.isEmpty) return;
    for (final id in _selectedTemplateIds.toList()) {
      _removeTemplateSnippet(id);
    }
    setState(() {
      _selectedTemplateIds.clear();
      _templateInsertedBlocks.clear();
    });
    _showTemplateToast('All template snippets removed.');
  }

  void _showTemplateToast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        duration: const Duration(milliseconds: 1300),
      ),
    );
  }

  void _scrollToInstructionsEditor() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final context = _instructionsEditorKey.currentContext;
      if (context == null) return;
      Scrollable.ensureVisible(
        context,
        duration: const Duration(milliseconds: 260),
        curve: Curves.easeOutCubic,
        alignment: 0.15,
      );
    });
  }

  Future<T> _runWithAuthRetry<T>(
    Future<T> Function(String accessToken) op,
  ) async {
    try {
      return await op(widget.session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      try {
        final refreshed = await widget.apiClient.refreshTokens(
          refreshToken: widget.session.refreshToken,
        );
        final nextSession = refreshed.toSession();
        widget.onSessionUpdated(nextSession);
        return await op(nextSession.accessToken);
      } on ApiException {
        widget.onSessionInvalid();
        rethrow;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final hasActiveJob =
        _activeJobStatus != null && !_activeJobStatus!.isTerminal;
    final progress = _activeJobStatus?.progress ?? 0;
    return Scaffold(
      body: Stack(
        children: [
          const _ExamBackground(),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: GlassContainer(
                borderRadius: 22,
                child: Column(
                  children: [
                    Expanded(
                      child: ListView(
                        padding: const EdgeInsets.fromLTRB(16, 18, 16, 16),
                        children: [
                          _SectionTitle('Generation Type'),
                          const SizedBox(height: 8),
                          Wrap(
                            spacing: 8,
                            runSpacing: 8,
                            children: _generationTypes.map((type) {
                              final active = _generationType == type;
                              return ChoiceChip(
                                label: Text(type.toUpperCase()),
                                selected: active,
                                onSelected: (_) => setState(() {
                                  _generationType = type;
                                  if (type != 'exam') {
                                    _examSectionMode = 'mixed';
                                  }
                                }),
                                selectedColor: AppColors.primary.withValues(
                                  alpha: 0.25,
                                ),
                                labelStyle: TextStyle(
                                  color: active
                                      ? AppColors.primary
                                      : Colors.white70,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w700,
                                ),
                              );
                            }).toList(),
                          ),
                          const SizedBox(height: 18),
                          _SectionTitle('Select Documents'),
                          const SizedBox(height: 8),
                          if (_selectedCbcNoteIds.isNotEmpty)
                            Padding(
                              padding: const EdgeInsets.only(bottom: 8),
                              child: Text(
                                'Shared notes selected: ${_selectedCbcNoteIds.length}',
                                style: const TextStyle(
                                  color: AppColors.accent,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          if (_isLoadingDocuments)
                            const Padding(
                              padding: EdgeInsets.symmetric(vertical: 8),
                              child: LinearProgressIndicator(minHeight: 3),
                            ),
                          if (!_isLoadingDocuments && _documents.isEmpty)
                            const Text(
                              'No uploaded documents found. Upload first.',
                              style: TextStyle(color: AppColors.textMuted),
                            ),
                          if (_documents.isNotEmpty)
                            ..._documents.map(
                              (doc) => CheckboxListTile(
                                value: _selectedDocumentIds.contains(doc.id),
                                onChanged: (selected) {
                                  setState(() {
                                    if (selected ?? false) {
                                      _selectedDocumentIds.add(doc.id);
                                    } else {
                                      _selectedDocumentIds.remove(doc.id);
                                    }
                                  });
                                },
                                controlAffinity:
                                    ListTileControlAffinity.leading,
                                title: Text(
                                  doc.filename,
                                  style: const TextStyle(fontSize: 13),
                                ),
                                subtitle: Text(
                                  '${doc.fileType.toUpperCase()} â€¢ ${doc.totalChunks} chunks\n${_documentRetentionLabel(doc)}',
                                  style: const TextStyle(fontSize: 11),
                                ),
                              ),
                            ),
                          const SizedBox(height: 10),
                          if (_generationType == 'exam') ...[
                            _SectionTitle('Exam Blueprint'),
                            const SizedBox(height: 8),
                            SwitchListTile(
                              contentPadding: EdgeInsets.zero,
                              value: _useBlueprint,
                              onChanged: (v) =>
                                  setState(() => _useBlueprint = v),
                              title: const Text(
                                'Use smart paper blueprint',
                                style: TextStyle(
                                  fontSize: 13,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              subtitle: const Text(
                                'Auto-target level, subject, and paper format for stronger generation.',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: AppColors.textMuted,
                                ),
                              ),
                            ),
                            const SizedBox(height: 6),
                            const Text(
                              'Level',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                color: AppColors.textMuted,
                              ),
                            ),
                            const SizedBox(height: 8),
                            SizedBox(
                              height: 38,
                              child: ListView.separated(
                                scrollDirection: Axis.horizontal,
                                itemCount: _levelOptions.length,
                                separatorBuilder: (_, __) =>
                                    const SizedBox(width: 8),
                                itemBuilder: (context, idx) {
                                  final level = _levelOptions[idx];
                                  final selected = _selectedLevel == level;
                                  return ChoiceChip(
                                    label: Text(level),
                                    selected: selected,
                                    onSelected: (_) =>
                                        _onBlueprintLevelSelected(level),
                                  );
                                },
                              ),
                            ),
                            const SizedBox(height: 10),
                            const Text(
                              'Subject',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                color: AppColors.textMuted,
                              ),
                            ),
                            const SizedBox(height: 8),
                            SizedBox(
                              height: 38,
                              child: ListView.separated(
                                scrollDirection: Axis.horizontal,
                                itemCount: _subjectsForLevel(
                                  _selectedLevel,
                                ).length,
                                separatorBuilder: (_, __) =>
                                    const SizedBox(width: 8),
                                itemBuilder: (context, idx) {
                                  final subject = _subjectsForLevel(
                                    _selectedLevel,
                                  )[idx];
                                  final selected = _selectedSubject == subject;
                                  return ChoiceChip(
                                    label: Text(subject),
                                    selected: selected,
                                    onSelected: (_) =>
                                        _onBlueprintSubjectSelected(subject),
                                  );
                                },
                              ),
                            ),
                            const SizedBox(height: 10),
                            const Text(
                              'Paper',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                color: AppColors.textMuted,
                              ),
                            ),
                            const SizedBox(height: 8),
                            SizedBox(
                              height: 38,
                              child: ListView.separated(
                                scrollDirection: Axis.horizontal,
                                itemCount: _paperOptions.length,
                                separatorBuilder: (_, __) =>
                                    const SizedBox(width: 8),
                                itemBuilder: (context, idx) {
                                  final paper = _paperOptions[idx];
                                  final selected = _selectedPaper == paper;
                                  return ChoiceChip(
                                    label: Text(paper),
                                    selected: selected,
                                    onSelected: (_) =>
                                        _onBlueprintPaperSelected(paper),
                                  );
                                },
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Active target: ${_levelLabel(_selectedLevel)} $_selectedSubject $_selectedPaper',
                              style: const TextStyle(
                                fontSize: 12,
                                color: AppColors.accent,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              _paperGuideText(),
                              style: const TextStyle(
                                fontSize: 11,
                                color: AppColors.textMuted,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 14),
                          ],
                          _SectionTitle('Topic and Difficulty'),
                          const SizedBox(height: 8),
                          TextField(
                            controller: _topicController,
                            decoration: const InputDecoration(
                              hintText: 'Optional topic focus',
                            ),
                          ),
                          const SizedBox(height: 10),
                          DropdownButtonFormField<String>(
                            value: _difficulty,
                            items: const [
                              DropdownMenuItem(
                                value: 'easy',
                                child: Text('Easy'),
                              ),
                              DropdownMenuItem(
                                value: 'medium',
                                child: Text('Medium'),
                              ),
                              DropdownMenuItem(
                                value: 'hard',
                                child: Text('Hard'),
                              ),
                            ],
                            onChanged: (value) {
                              if (value != null) {
                                setState(() => _difficulty = value);
                              }
                            },
                            decoration: const InputDecoration(
                              labelText: 'Difficulty',
                            ),
                          ),
                          const SizedBox(height: 10),
                          if (_generationType == 'exam')
                            TextField(
                              controller: _marksController,
                              keyboardType: TextInputType.number,
                              decoration: const InputDecoration(
                                labelText: 'Total marks',
                              ),
                            ),
                          if (_generationType == 'exam') ...[
                            const SizedBox(height: 10),
                            const Text(
                              'Paper Section Style',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                color: AppColors.textMuted,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Wrap(
                              spacing: 8,
                              runSpacing: 8,
                              children: [
                                ChoiceChip(
                                  label: const Text('Mixed'),
                                  selected: _examSectionMode == 'mixed',
                                  onSelected: (_) => setState(
                                    () => _examSectionMode = 'mixed',
                                  ),
                                ),
                                ChoiceChip(
                                  label: const Text('Question + Marks'),
                                  selected:
                                      _examSectionMode == 'structured_only',
                                  onSelected: (_) => setState(
                                    () => _examSectionMode = 'structured_only',
                                  ),
                                ),
                                ChoiceChip(
                                  label: const Text('Multiple Choice'),
                                  selected: _examSectionMode == 'mcq_only',
                                  onSelected: (_) => setState(
                                    () => _examSectionMode = 'mcq_only',
                                  ),
                                ),
                                ChoiceChip(
                                  label: const Text('Essay'),
                                  selected: _examSectionMode == 'essay_only',
                                  onSelected: (_) => setState(
                                    () => _examSectionMode = 'essay_only',
                                  ),
                                ),
                              ],
                            ),
                          ],
                          if (_generationType == 'quiz' ||
                              _generationType == 'examples')
                            TextField(
                              controller: _questionsController,
                              keyboardType: TextInputType.number,
                              decoration: const InputDecoration(
                                labelText: 'Number of questions',
                              ),
                            ),
                          const SizedBox(height: 10),
                          GlassContainer(
                            borderRadius: 14,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12,
                              vertical: 8,
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                InkWell(
                                  onTap: () => setState(
                                    () => _templatesExpanded =
                                        !_templatesExpanded,
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(
                                        Icons.auto_fix_high_rounded,
                                        color: AppColors.accent,
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Text(
                                          'Prompt Templates (${_selectedTemplateIds.length} selected)',
                                          style: const TextStyle(
                                            fontWeight: FontWeight.w700,
                                          ),
                                        ),
                                      ),
                                      Container(
                                        padding: const EdgeInsets.symmetric(
                                          horizontal: 8,
                                          vertical: 4,
                                        ),
                                        decoration: BoxDecoration(
                                          color: AppColors.primary.withValues(
                                            alpha: 0.2,
                                          ),
                                          borderRadius: BorderRadius.circular(
                                            999,
                                          ),
                                          border: Border.all(
                                            color: AppColors.primary.withValues(
                                              alpha: 0.45,
                                            ),
                                          ),
                                        ),
                                        child: Text(
                                          '${_visibleTemplates().length}',
                                          style: const TextStyle(
                                            fontSize: 11,
                                            fontWeight: FontWeight.w700,
                                          ),
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Icon(
                                        _templatesExpanded
                                            ? Icons.expand_less_rounded
                                            : Icons.expand_more_rounded,
                                      ),
                                    ],
                                  ),
                                ),
                                AnimatedSize(
                                  duration: const Duration(milliseconds: 220),
                                  curve: Curves.easeOutCubic,
                                  child: !_templatesExpanded
                                      ? const SizedBox.shrink()
                                      : Column(
                                          crossAxisAlignment:
                                              CrossAxisAlignment.start,
                                          children: [
                                            const SizedBox(height: 10),
                                            const Text(
                                              'Only school header template is kept active for manual branding. Blueprint chips above drive the core paper logic.',
                                              style: TextStyle(
                                                fontSize: 12,
                                                color: AppColors.textMuted,
                                              ),
                                            ),
                                            const SizedBox(height: 10),
                                            Container(
                                              width: double.infinity,
                                              padding: const EdgeInsets.all(10),
                                              decoration: BoxDecoration(
                                                color: AppColors.primary
                                                    .withValues(alpha: 0.10),
                                                borderRadius:
                                                    BorderRadius.circular(10),
                                                border: Border.all(
                                                  color: AppColors.primary
                                                      .withValues(alpha: 0.28),
                                                ),
                                              ),
                                              child: Text(
                                                _generationType == 'exam'
                                                    ? 'Context: You are generating an EXAM (${_examSectionMode == 'mixed' ? 'mixed sections' : _examSectionMode.replaceAll('_', ' ')}). Choose templates that match this paper style.'
                                                    : 'Context: You are generating ${_generationType.toUpperCase()}. Choose templates that improve clarity and relevance.',
                                                style: const TextStyle(
                                                  fontSize: 12,
                                                  color: AppColors.textMuted,
                                                  height: 1.35,
                                                ),
                                              ),
                                            ),
                                            const SizedBox(height: 10),
                                            ..._visibleTemplates().map(
                                              (template) => Padding(
                                                padding: const EdgeInsets.only(
                                                  bottom: 8,
                                                ),
                                                child: InkWell(
                                                  onTap: () =>
                                                      _toggleTemplateSelection(
                                                        template,
                                                      ),
                                                  child: Container(
                                                    decoration: BoxDecoration(
                                                      color:
                                                          _selectedTemplateIds
                                                              .contains(
                                                                template.id,
                                                              )
                                                          ? AppColors.primary
                                                                .withValues(
                                                                  alpha: 0.18,
                                                                )
                                                          : Colors.white
                                                                .withValues(
                                                                  alpha: 0.03,
                                                                ),
                                                      borderRadius:
                                                          BorderRadius.circular(
                                                            12,
                                                          ),
                                                      border: Border.all(
                                                        color:
                                                            _selectedTemplateIds
                                                                .contains(
                                                                  template.id,
                                                                )
                                                            ? AppColors.primary
                                                                  .withValues(
                                                                    alpha: 0.45,
                                                                  )
                                                            : Colors.white12,
                                                      ),
                                                    ),
                                                    padding:
                                                        const EdgeInsets.all(
                                                          10,
                                                        ),
                                                    child: Row(
                                                      crossAxisAlignment:
                                                          CrossAxisAlignment
                                                              .start,
                                                      children: [
                                                        Icon(
                                                          _selectedTemplateIds
                                                                  .contains(
                                                                    template.id,
                                                                  )
                                                              ? Icons
                                                                    .check_circle_rounded
                                                              : Icons
                                                                    .radio_button_unchecked_rounded,
                                                          size: 18,
                                                          color:
                                                              _selectedTemplateIds
                                                                  .contains(
                                                                    template.id,
                                                                  )
                                                              ? AppColors
                                                                    .primary
                                                              : AppColors
                                                                    .textMuted,
                                                        ),
                                                        const SizedBox(
                                                          width: 8,
                                                        ),
                                                        Expanded(
                                                          child: Column(
                                                            crossAxisAlignment:
                                                                CrossAxisAlignment
                                                                    .start,
                                                            children: [
                                                              Row(
                                                                children: [
                                                                  Expanded(
                                                                    child: Text(
                                                                      template
                                                                          .title,
                                                                      style: const TextStyle(
                                                                        fontWeight:
                                                                            FontWeight.w700,
                                                                      ),
                                                                    ),
                                                                  ),
                                                                  if (_selectedTemplateIds
                                                                      .contains(
                                                                        template
                                                                            .id,
                                                                      ))
                                                                    Container(
                                                                      padding: const EdgeInsets.symmetric(
                                                                        horizontal:
                                                                            7,
                                                                        vertical:
                                                                            3,
                                                                      ),
                                                                      decoration: BoxDecoration(
                                                                        color: Colors
                                                                            .greenAccent
                                                                            .withValues(
                                                                              alpha: 0.15,
                                                                            ),
                                                                        borderRadius:
                                                                            BorderRadius.circular(
                                                                              999,
                                                                            ),
                                                                        border: Border.all(
                                                                          color: Colors.greenAccent.withValues(
                                                                            alpha:
                                                                                0.45,
                                                                          ),
                                                                        ),
                                                                      ),
                                                                      child: const Text(
                                                                        'INSERTED',
                                                                        style: TextStyle(
                                                                          fontSize:
                                                                              10,
                                                                          fontWeight:
                                                                              FontWeight.w700,
                                                                          color:
                                                                              Colors.greenAccent,
                                                                        ),
                                                                      ),
                                                                    ),
                                                                ],
                                                              ),
                                                              const SizedBox(
                                                                height: 2,
                                                              ),
                                                              Text(
                                                                template
                                                                    .subtitle,
                                                                style: const TextStyle(
                                                                  color: AppColors
                                                                      .textMuted,
                                                                  fontSize: 12,
                                                                ),
                                                              ),
                                                            ],
                                                          ),
                                                        ),
                                                      ],
                                                    ),
                                                  ),
                                                ),
                                              ),
                                            ),
                                            if (_selectedTemplateIds.isNotEmpty)
                                              Align(
                                                alignment:
                                                    Alignment.centerRight,
                                                child: TextButton.icon(
                                                  onPressed:
                                                      _clearSelectedTemplates,
                                                  icon: const Icon(
                                                    Icons.clear_rounded,
                                                  ),
                                                  label: const Text(
                                                    'Clear Selections',
                                                  ),
                                                ),
                                              ),
                                          ],
                                        ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 10),
                          KeyedSubtree(
                            key: _instructionsEditorKey,
                            child: TextField(
                              controller: _instructionsController,
                              focusNode: _instructionsFocusNode,
                              maxLines: 8,
                              decoration: const InputDecoration(
                                hintText:
                                    'Additional instructions (templates append here for editing)',
                              ),
                            ),
                          ),
                          if (_error != null) ...[
                            const SizedBox(height: 12),
                            Text(
                              _error!,
                              style: const TextStyle(color: Colors.redAccent),
                            ),
                          ],
                          if (_latestQueuedJob != null ||
                              _activeJobStatus != null) ...[
                            const SizedBox(height: 12),
                            GlassContainer(
                              borderRadius: 14,
                              padding: const EdgeInsets.all(12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    children: [
                                      Icon(
                                        Icons.timelapse_rounded,
                                        color: _jobStatusColor(),
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Job Status: ${_jobStatusLabel()}',
                                        style: TextStyle(
                                          color: _jobStatusColor(),
                                          fontWeight: FontWeight.w700,
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 6),
                                  Text(
                                    'Job ID: ${_latestQueuedJob?.jobId ?? _activeJobStatus?.jobId ?? "-"}',
                                    style: const TextStyle(
                                      fontSize: 12,
                                      color: AppColors.textMuted,
                                    ),
                                  ),
                                  if (_latestQueuedJob?.estimatedTime != null)
                                    Text(
                                      'Estimated time: ${_latestQueuedJob!.estimatedTime}',
                                      style: const TextStyle(
                                        fontSize: 12,
                                        color: AppColors.textMuted,
                                      ),
                                    ),
                                  const SizedBox(height: 8),
                                  LinearProgressIndicator(
                                    value: progress.clamp(0, 100) / 100.0,
                                    minHeight: 7,
                                    borderRadius: BorderRadius.circular(999),
                                  ),
                                  const SizedBox(height: 8),
                                  Row(
                                    children: [
                                      TextButton.icon(
                                        onPressed: _openJobsScreen,
                                        icon: const Icon(
                                          Icons.schedule_rounded,
                                        ),
                                        label: const Text('My Jobs'),
                                      ),
                                      const Spacer(),
                                      if (_latestGeneration != null)
                                        OutlinedButton.icon(
                                          onPressed: _openLatestGeneration,
                                          icon: const Icon(
                                            Icons.open_in_new_rounded,
                                          ),
                                          label: const Text('Open Output'),
                                        ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ],
                          const SizedBox(height: 14),
                          SizedBox(
                            width: double.infinity,
                            child: ElevatedButton.icon(
                              onPressed: (_isGenerating || hasActiveJob)
                                  ? null
                                  : _generate,
                              style: ElevatedButton.styleFrom(
                                backgroundColor: AppColors.primary,
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(
                                  vertical: 14,
                                ),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(14),
                                ),
                              ),
                              icon: _isGenerating
                                  ? const SizedBox(
                                      height: 16,
                                      width: 16,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: Colors.white,
                                      ),
                                    )
                                  : Icon(_generationType == 'chat' ? Icons.chat_bubble_outline_rounded : Icons.bolt),
                              label: Text(
                                _isGenerating
                                    ? 'Queueing...'
                                    : hasActiveJob
                                    ? 'Generation In Progress'
                                    : _latestGeneration != null
                                    ? 'Generate New'
                                    : 'Generate',
                                style: const TextStyle(
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ),
                          const SizedBox(height: 16),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text.toUpperCase(),
      style: const TextStyle(
        color: AppColors.primary,
        letterSpacing: 1.8,
        fontSize: 11,
        fontWeight: FontWeight.w700,
      ),
    );
  }
}

class _ExamBackground extends StatelessWidget {
  const _ExamBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: RadialGradient(
          colors: [Color(0xFF0B1220), Color(0xFF020617)],
          radius: 1.2,
          center: Alignment(0.4, -0.6),
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            top: -120,
            right: -100,
            child: _GlowCircle(
              color: AppColors.primary.withValues(alpha: 0.12),
            ),
          ),
          Positioned(
            bottom: -140,
            left: -120,
            child: _GlowCircle(
              color: Colors.blueAccent.withValues(alpha: 0.08),
            ),
          ),
        ],
      ),
    );
  }
}

class _GlowCircle extends StatelessWidget {
  const _GlowCircle({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 260,
      width: 260,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [BoxShadow(color: color, blurRadius: 120, spreadRadius: 20)],
      ),
    );
  }
}

class _PromptTemplate {
  const _PromptTemplate({
    required this.id,
    required this.title,
    required this.subtitle,
    required this.body,
    this.requiresSchoolName = false,
    this.requiresExamTitle = false,
    this.recommendedFor = const {},
  });

  final String id;
  final String title;
  final String subtitle;
  final String body;
  final bool requiresSchoolName;
  final bool requiresExamTitle;
  final Set<String> recommendedFor;
}



