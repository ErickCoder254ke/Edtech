import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'exam_configurator_screen.dart';

class NotesCatalogScreen extends StatefulWidget {
  const NotesCatalogScreen({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onSessionUpdated,
    required this.onSessionInvalid,
  });

  final ApiClient apiClient;
  final Session session;
  final ValueChanged<Session> onSessionUpdated;
  final VoidCallback onSessionInvalid;

  @override
  State<NotesCatalogScreen> createState() => _NotesCatalogScreenState();
}

class _NotesCatalogScreenState extends State<NotesCatalogScreen> {
  bool _loading = true;
  List<CbcNote> _notes = const [];
  CbcNoteCategories _categories = CbcNoteCategories(grades: const [], subjectsByGrade: const {});
  int? _selectedGrade;
  String? _selectedSubject;
  final TextEditingController _searchController = TextEditingController();
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadCategoriesAndNotes();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String accessToken) op) async {
    try {
      return await op(widget.session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      final refreshed = await widget.apiClient.refreshTokens(
        refreshToken: widget.session.refreshToken,
      );
      final next = refreshed.toSession();
      widget.onSessionUpdated(next);
      return await op(next.accessToken);
    }
  }

  Future<void> _loadCategoriesAndNotes() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final categories = await _runWithAuthRetry(
        (token) => widget.apiClient.listCbcNoteCategories(accessToken: token),
      );
      int? grade = _selectedGrade;
      if (grade == null && categories.grades.isNotEmpty) {
        grade = categories.grades.first;
      }
      final availableSubjects = categories.subjectsByGrade['${grade ?? 0}'] ?? const <String>[];
      String? subject = _selectedSubject;
      if (subject != null && !availableSubjects.contains(subject)) {
        subject = null;
      }
      final notes = await _runWithAuthRetry(
        (token) => widget.apiClient.listCbcNotes(
          accessToken: token,
          grade: grade,
          subject: subject,
          q: _searchController.text.trim().isEmpty ? null : _searchController.text.trim(),
          limit: 200,
        ),
      );
      if (!mounted) return;
      setState(() {
        _categories = categories;
        _selectedGrade = grade;
        _selectedSubject = subject;
        _notes = notes;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load notes.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _reloadNotesOnly() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final notes = await _runWithAuthRetry(
        (token) => widget.apiClient.listCbcNotes(
          accessToken: token,
          grade: _selectedGrade,
          subject: _selectedSubject,
          q: _searchController.text.trim().isEmpty ? null : _searchController.text.trim(),
          limit: 200,
        ),
      );
      if (!mounted) return;
      setState(() => _notes = notes);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _openGeneratorForNote(CbcNote note) async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ExamConfiguratorScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onSessionInvalid,
          initialCbcNoteIds: [note.id],
          initialTopic: '${note.levelLabel} ${note.subject}',
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final subjects = _categories.subjectsByGrade['${_selectedGrade ?? 0}'] ?? const <String>[];
    return Scaffold(
      appBar: AppBar(
        title: const Text('CBC / Senior School Notes'),
        actions: [
          IconButton(
            onPressed: _loadCategoriesAndNotes,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _loadCategoriesAndNotes,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 28),
          children: [
            GlassContainer(
              borderRadius: 16,
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Select category, review notes, then generate from selected content.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: _categories.grades
                        .map(
                          (grade) => ChoiceChip(
                            label: Text('Form/Grade $grade'),
                            selected: _selectedGrade == grade,
                            onSelected: (_) {
                              if (_selectedGrade == grade) return;
                              setState(() {
                                _selectedGrade = grade;
                                _selectedSubject = null;
                              });
                              _reloadNotesOnly();
                            },
                          ),
                        )
                        .toList(),
                  ),
                  if (subjects.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          ChoiceChip(
                            label: const Text('All Subjects'),
                            selected: _selectedSubject == null,
                            onSelected: (_) {
                              if (_selectedSubject == null) return;
                              setState(() => _selectedSubject = null);
                              _reloadNotesOnly();
                            },
                          ),
                          const SizedBox(width: 8),
                          ...subjects.map(
                            (s) => Padding(
                              padding: const EdgeInsets.only(right: 8),
                              child: ChoiceChip(
                                label: Text(s),
                                selected: _selectedSubject == s,
                                onSelected: (_) {
                                  if (_selectedSubject == s) return;
                                  setState(() => _selectedSubject = s);
                                  _reloadNotesOnly();
                                },
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                  const SizedBox(height: 10),
                  TextField(
                    controller: _searchController,
                    onSubmitted: (_) => _reloadNotesOnly(),
                    decoration: InputDecoration(
                      hintText: 'Search notes by title or subject',
                      suffixIcon: IconButton(
                        onPressed: _reloadNotesOnly,
                        icon: const Icon(Icons.search_rounded),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            if (_loading) const LinearProgressIndicator(minHeight: 3),
            if (_error != null) ...[
              const SizedBox(height: 10),
              Text(_error!, style: const TextStyle(color: Colors.redAccent)),
            ],
            const SizedBox(height: 10),
            if (!_loading && _notes.isEmpty)
              const Text(
                'No notes found for this category yet.',
                style: TextStyle(color: AppColors.textMuted),
              )
            else
              ..._notes.map(
                (note) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: GlassContainer(
                    borderRadius: 14,
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          note.title,
                          style: const TextStyle(fontWeight: FontWeight.w700),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          '${note.levelLabel} - ${note.subject} - ${(note.fileSize / 1024 / 1024).toStringAsFixed(1)} MB',
                          style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                        ),
                        if ((note.description ?? '').isNotEmpty) ...[
                          const SizedBox(height: 4),
                          Text(
                            note.description!,
                            style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                          ),
                        ],
                        const SizedBox(height: 10),
                        Row(
                          children: [
                            Expanded(
                              child: FilledButton.icon(
                                onPressed: () => _openGeneratorForNote(note),
                                icon: const Icon(Icons.auto_awesome_rounded),
                                label: const Text('Generate From Note'),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

