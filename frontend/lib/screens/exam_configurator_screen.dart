import 'dart:async';

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'generation_viewer_screen.dart';
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
  ];

  String _generationType = 'exam';
  String _difficulty = 'medium';
  bool _isLoadingDocuments = true;
  bool _isGenerating = false;
  bool _isPollingJob = false;
  String? _error;
  GenerationResponse? _latestGeneration;
  GenerationJobResponse? _latestQueuedJob;
  JobStatusResponse? _activeJobStatus;
  Timer? _jobPollTimer;
  bool _templatesExpanded = true;
  final Set<String> _selectedTemplateIds = <String>{};
  final Map<String, String> _templateInsertedBlocks = <String, String>{};
  static const List<_PromptTemplate> _promptTemplates = [
    _PromptTemplate(
      id: 'single_section_no_mcq_essay',
      title: 'Single Section (Question + Marks)',
      subtitle: 'No MCQ or essay. Structured questions only.',
      body:
          'Create ONE section only. Each item must be written as "Question ... (X marks)". '
          'Do not include multiple-choice or essay questions. Use only structured/short and medium response items. '
          'Ensure each question is clearly stated using verbs like State, Explain, Identify, Describe, and Calculate. '
          'Distribute marks realistically based on cognitive load and expected answer length.',
      recommendedFor: {'exam'},
    ),
    _PromptTemplate(
      id: 'institution_header_custom',
      title: 'School + Term Header',
      subtitle: 'Inject school name and exam title.',
      body:
          'Use the school name "{{school_name}}" in the exam header. '
          'Set exam title to "{{exam_title}}" and keep professional formatting. '
          'Include class level, subject, total marks, and time allowed in header.',
      requiresSchoolName: true,
      requiresExamTitle: true,
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'marking_realism',
      title: 'Marking Realism Guard',
      subtitle: 'Align complexity to marks.',
      body:
          'Make mark allocation realistic: 1-2 marks for factual recall, 3-5 for short explanations, '
          '6+ for multi-step reasoning. Avoid over-weighting simple recall tasks. '
          'Ensure total marks exactly match requested marks.',
      recommendedFor: {'exam', 'quiz'},
    ),
    _PromptTemplate(
      id: 'directive_verbs',
      title: 'Directive Verb Quality',
      subtitle: 'Clear exam-style command terms.',
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

    setState(() {
      _isGenerating = true;
      _error = null;
    });

    try {
      final request = GenerationRequest(
        documentIds: _selectedDocumentIds.toList(),
        cbcNoteIds: _selectedCbcNoteIds.toList(),
        generationType: _generationType,
        topic: _topicController.text.trim().isEmpty
            ? null
            : _topicController.text.trim(),
        difficulty: _difficulty,
        marks: _generationType == 'exam'
            ? int.tryParse(_marksController.text.trim())
            : null,
        numQuestions:
            (_generationType == 'quiz' || _generationType == 'examples')
            ? int.tryParse(_questionsController.text.trim())
            : null,
        questionTypes: _generationType == 'exam'
            ? const ['mcq', 'structured', 'essay']
            : _generationType == 'quiz'
            ? const ['mcq', 'structured']
            : null,
        additionalInstructions: _instructionsController.text.trim().isEmpty
            ? null
            : _instructionsController.text.trim(),
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

  void _showSubscriptionPrompt(String message) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Upgrade Required'),
        content: Text(
          '$message\n\nYou have reached your current generation limit. Choose a subscription to continue.',
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

  List<_PromptTemplate> _visibleTemplates() {
    return _promptTemplates
        .where((t) => t.recommendedFor.contains(_generationType))
        .toList();
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
                  labelText: 'Exam title',
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

  String _appendInstructionSnippet(String templateId, String snippet) {
    final current = _instructionsController.text.trim();
    final header = 'Template[$templateId]:';
    final block = '$header $snippet';
    final next = current.isEmpty ? block : '$current\n\n$block';
    _instructionsController.text = next;
    _instructionsController.selection = TextSelection.fromPosition(
      TextPosition(offset: _instructionsController.text.length),
    );
    _instructionsFocusNode.requestFocus();
    _scrollToInstructionsEditor();
    return block;
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
                                onSelected: (_) =>
                                    setState(() => _generationType = type),
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
                                  '${doc.fileType.toUpperCase()} • ${doc.totalChunks} chunks',
                                  style: const TextStyle(fontSize: 11),
                                ),
                              ),
                            ),
                          const SizedBox(height: 10),
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
                                              'Tap one or more templates to append high-quality instructions.',
                                              style: TextStyle(
                                                fontSize: 12,
                                                color: AppColors.textMuted,
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
                                  SizedBox(
                                    width: double.infinity,
                                    child: OutlinedButton.icon(
                                      onPressed: _openJobsScreen,
                                      icon: const Icon(Icons.schedule_rounded),
                                      label: const Text('Open My Jobs'),
                                    ),
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
                                  : const Icon(Icons.bolt),
                              label: Text(
                                _isGenerating
                                    ? 'Queueing...'
                                    : hasActiveJob
                                    ? 'Generation In Progress'
                                    : 'Generate',
                                style: const TextStyle(
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ),
                          if (_latestGeneration != null) ...[
                            const SizedBox(height: 10),
                            SizedBox(
                              width: double.infinity,
                              child: OutlinedButton.icon(
                                onPressed: () {
                                  final latest = _latestGeneration;
                                  if (latest == null) return;
                                  Navigator.of(context).push(
                                    MaterialPageRoute(
                                      builder: (_) => GenerationViewerScreen(
                                        generation: latest,
                                      ),
                                    ),
                                  );
                                },
                                icon: const Icon(Icons.open_in_new_rounded),
                                label: Text(
                                  'Open Latest ${_latestGeneration!.generationType.toUpperCase()}',
                                  style: const TextStyle(
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                              ),
                            ),
                          ],
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
