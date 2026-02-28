import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'generation_viewer_screen.dart';

class LibraryScreen extends StatefulWidget {
  const LibraryScreen({
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
  State<LibraryScreen> createState() => _LibraryScreenState();
}

class _LibraryScreenState extends State<LibraryScreen> {
  bool _loading = true;
  bool _openingGeneration = false;
  String? _error;
  List<DocumentMetadata> _documents = [];
  List<GenerationResponse> _generations = [];
  final Set<String> _deletingDocumentIds = <String>{};
  final Set<String> _deletingGenerationIds = <String>{};

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  @override
  void didUpdateWidget(covariant LibraryScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadData();
    }
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String accessToken) op) async {
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

  Future<void> _loadData() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final docsFuture = _runWithAuthRetry(
        (token) => widget.apiClient.listDocuments(token, limit: 100),
      );
      final gensFuture = _runWithAuthRetry(
        (token) => widget.apiClient.listGenerations(token, limit: 100, compact: true),
      );
      final results = await Future.wait<dynamic>([docsFuture, gensFuture]);
      final docs = results[0] as List<DocumentMetadata>;
      final gens = results[1] as List<GenerationResponse>;
      if (!mounted) return;
      setState(() {
        _documents = docs;
        _generations = gens;
      });
    } on ApiException catch (error) {
      setState(() => _error = error.message);
    } catch (_) {
      setState(() => _error = 'Unable to load library data.');
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _openGeneration(GenerationResponse gen) async {
    if (_openingGeneration) return;
    setState(() => _openingGeneration = true);
    try {
      final resolved = gen.content.isNotEmpty
          ? gen
          : await _runWithAuthRetry(
              (token) => widget.apiClient.getGeneration(
                accessToken: token,
                generationId: gen.id,
              ),
            );
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => GenerationViewerScreen(generation: resolved),
        ),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _openingGeneration = false);
    }
  }

  Future<void> _deleteDocument(DocumentMetadata doc) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Document?'),
        content: Text(
          'This will remove "${doc.filename}" and all related chunks.\n\n'
          'Note: deletion does not restore upload quota usage.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() => _deletingDocumentIds.add(doc.id));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.deleteDocument(
          accessToken: token,
          documentId: doc.id,
        ),
      );
      if (!mounted) return;
      setState(() {
        _documents.removeWhere((d) => d.id == doc.id);
      });
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Deleted ${doc.filename}')),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    } finally {
      if (mounted) {
        setState(() => _deletingDocumentIds.remove(doc.id));
      }
    }
  }

  Future<void> _deleteGeneration(GenerationResponse gen) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Generation?'),
        content: Text(
          'Delete this ${gen.generationType} output from your library?\n\n'
          'Note: deletion does not restore generation quota usage.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() => _deletingGenerationIds.add(gen.id));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.deleteGeneration(
          accessToken: token,
          generationId: gen.id,
        ),
      );
      if (!mounted) return;
      setState(() {
        _generations.removeWhere((g) => g.id == gen.id);
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Generation deleted')),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    } finally {
      if (mounted) {
        setState(() => _deletingGenerationIds.remove(gen.id));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          const _LibraryBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadData,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(24, 20, 24, 120),
                children: [
                  const SizedBox(height: 6),
                  if (_loading) const _LoadingCard(),
                  if (_error != null) _ErrorCard(message: _error!),
                  if (!_loading && _error == null) ...[
                    const _SectionTitle('Documents'),
                    const SizedBox(height: 12),
                    if (_documents.isEmpty)
                      const _EmptyState(
                        title: 'No documents yet',
                        subtitle: 'Upload a PDF, DOCX, or TXT to build your library.',
                      )
                    else
                      ..._documents.map(
                        (doc) => _DocumentTile(
                          doc: doc,
                          isDeleting: _deletingDocumentIds.contains(doc.id),
                          onDelete: () => _deleteDocument(doc),
                        ),
                      ),
                    const SizedBox(height: 24),
                    const _SectionTitle('Recent Generations'),
                    const SizedBox(height: 12),
                    if (_generations.isEmpty)
                      const _EmptyState(
                        title: 'No generations yet',
                        subtitle: 'Create summaries, quizzes, or exams to see them here.',
                      )
                    else
                      ..._generations.map(
                        (gen) => _GenerationTile(
                          gen: gen,
                          isDeleting: _deletingGenerationIds.contains(gen.id),
                          onTap: () => _openGeneration(gen),
                          onDelete: () => _deleteGeneration(gen),
                        ),
                      ),
                  ],
                ],
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
        color: AppColors.textMuted,
        fontWeight: FontWeight.w700,
        letterSpacing: 2.2,
        fontSize: 11,
      ),
    );
  }
}

class _DocumentTile extends StatelessWidget {
  const _DocumentTile({
    required this.doc,
    required this.onDelete,
    required this.isDeleting,
  });

  final DocumentMetadata doc;
  final VoidCallback onDelete;
  final bool isDeleting;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: GlassContainer(
        borderRadius: 18,
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Container(
              height: 44,
              width: 44,
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
              ),
              child: const Icon(Icons.description, color: AppColors.primary),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    doc.filename,
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${doc.fileType.toUpperCase()} • ${doc.totalChunks} chunks',
                    style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                  ),
                ],
              ),
            ),
            IconButton(
              onPressed: isDeleting ? null : onDelete,
              icon: isDeleting
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.delete_outline_rounded, color: Colors.redAccent),
            ),
          ],
        ),
      ),
    );
  }
}

class _GenerationTile extends StatelessWidget {
  const _GenerationTile({
    required this.gen,
    required this.onTap,
    required this.onDelete,
    required this.isDeleting,
  });

  final GenerationResponse gen;
  final VoidCallback onTap;
  final VoidCallback onDelete;
  final bool isDeleting;

  String _formatDate(DateTime date) {
    final local = date.toLocal();
    final year = local.year.toString().padLeft(4, '0');
    final month = local.month.toString().padLeft(2, '0');
    final day = local.day.toString().padLeft(2, '0');
    return '$year-$month-$day';
  }

  String _titleForType(String type) {
    switch (type) {
      case 'summary':
        return 'Summary';
      case 'concepts':
        return 'Concept Map';
      case 'examples':
        return 'Worked Examples';
      case 'quiz':
        return 'Revision Quiz';
      case 'exam':
        return 'Exam Paper';
      default:
        return type;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: GestureDetector(
        onTap: onTap,
        child: GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(14),
          child: Row(
            children: [
              Container(
                height: 44,
                width: 44,
                decoration: BoxDecoration(
                  color: AppColors.accent.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppColors.accent.withValues(alpha: 0.4)),
                ),
                child: const Icon(Icons.auto_awesome, color: AppColors.accent),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _titleForType(gen.generationType),
                      style: const TextStyle(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Generated ${_formatDate(gen.createdAt)}',
                      style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                    ),
                  ],
                ),
              ),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    onPressed: isDeleting ? null : onDelete,
                    icon: isDeleting
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.delete_outline_rounded, color: Colors.redAccent),
                  ),
                  const Icon(Icons.chevron_right, color: Colors.white54),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard();

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(18),
      child: Row(
        children: const [
          SizedBox(
            height: 20,
            width: 20,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          SizedBox(width: 12),
          Text('Loading your library...'),
        ],
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  const _ErrorCard({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          const Icon(Icons.error_outline, color: Colors.redAccent),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(color: Colors.redAccent),
            ),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.title, required this.subtitle});

  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
          const SizedBox(height: 6),
          Text(subtitle, style: const TextStyle(color: AppColors.textMuted)),
        ],
      ),
    );
  }
}

class _LibraryBackground extends StatelessWidget {
  const _LibraryBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF0A0F18), Color(0xFF111827)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            top: 80,
            left: -80,
            child: _GlowCircle(color: AppColors.accent.withValues(alpha: 0.08)),
          ),
          Positioned(
            bottom: -80,
            right: -60,
            child: _GlowCircle(color: AppColors.primary.withValues(alpha: 0.12)),
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
      height: 220,
      width: 220,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [
          BoxShadow(
            color: color,
            blurRadius: 120,
            spreadRadius: 20,
          ),
        ],
      ),
    );
  }
}
