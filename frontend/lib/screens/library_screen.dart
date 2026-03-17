import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../theme/tokens.dart';
import '../widgets/glass_container.dart';
import '../widgets/ui_snackbar.dart';
import '../widgets/ui_mesh_background.dart';
import '../widgets/skeleton_box.dart';
import 'generation_viewer_screen.dart';

enum _LibrarySection { all, documents, generations }

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

class _LibraryHeader extends StatelessWidget {
  const _LibraryHeader({
    required this.name,
    required this.loading,
    required this.itemCount,
  });

  final String name;
  final bool loading;
  final int itemCount;

  @override
  Widget build(BuildContext context) {
    final initials = (name.trim().isNotEmpty ? name.trim()[0] : '?').toUpperCase();
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Exam Library',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -0.2,
                ),
              ),
              const SizedBox(height: 4),
              Row(
                children: [
                  _Pill(
                    label: loading ? 'Syncing...' : '$itemCount items',
                    color: AppColors.primary.withValues(alpha: 0.16),
                    textColor: AppColors.textPrimary,
                    borderColor: AppColors.primary.withValues(alpha: 0.4),
                  ),
                  const SizedBox(width: 8),
                  _Pill(
                    label: 'Updated just now',
                    color: Colors.white.withValues(alpha: 0.05),
                    textColor: AppColors.textMuted,
                    borderColor: Colors.white.withValues(alpha: 0.08),
                  ),
                ],
              ),
            ],
          ),
        ),
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: const LinearGradient(
              colors: [AppColors.primary, AppColors.electric],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            boxShadow: [
              BoxShadow(
                color: AppColors.primary.withValues(alpha: 0.35),
                blurRadius: 16,
                spreadRadius: 1,
              )
            ],
          ),
          child: CircleAvatar(
            radius: 18,
            backgroundColor: AppColors.backgroundDark,
            child: Text(
              initials,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _SearchBar extends StatelessWidget {
  const _SearchBar({
    required this.controller,
    required this.onChanged,
    required this.onClear,
  });

  final TextEditingController controller;
  final ValueChanged<String> onChanged;
  final VoidCallback onClear;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(16),
        color: Colors.white.withValues(alpha: 0.04),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Row(
        children: [
          const Icon(Icons.search_rounded, color: AppColors.textMuted),
          const SizedBox(width: 10),
          Expanded(
            child: TextField(
              controller: controller,
              onChanged: onChanged,
              style: const TextStyle(fontWeight: FontWeight.w600),
              decoration: const InputDecoration(
                hintText: 'Search documents or generations',
                hintStyle: TextStyle(color: AppColors.textMuted),
                border: InputBorder.none,
              ),
            ),
          ),
          if (controller.text.isNotEmpty)
            IconButton(
              onPressed: onClear,
              icon: const Icon(Icons.close_rounded, size: 18, color: AppColors.textMuted),
            ),
          const SizedBox(width: 4),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(12),
              color: AppColors.primary.withValues(alpha: 0.18),
              border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
            ),
            child: Row(
              children: const [
                Icon(Icons.tune_rounded, size: 16, color: AppColors.primary),
                SizedBox(width: 6),
                Text(
                  'Filters',
                  style: TextStyle(
                    color: AppColors.primary,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.2,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _SectionChips extends StatelessWidget {
  const _SectionChips({required this.active, required this.onChanged});

  final _LibrarySection active;
  final ValueChanged<_LibrarySection> onChanged;

  @override
  Widget build(BuildContext context) {
    const items = [
      (_LibrarySection.all, 'All'),
      (_LibrarySection.documents, 'Documents'),
      (_LibrarySection.generations, 'Generations'),
    ];

    return Container(
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Row(
        children: [
          for (final entry in items)
            Expanded(
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                margin: const EdgeInsets.symmetric(horizontal: 4),
                decoration: BoxDecoration(
                  color: active == entry.$1
                      ? AppColors.primary.withValues(alpha: 0.22)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: active == entry.$1
                        ? AppColors.primary.withValues(alpha: 0.45)
                        : Colors.transparent,
                  ),
                ),
                child: InkWell(
                  borderRadius: BorderRadius.circular(12),
                  onTap: () => onChanged(entry.$1),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    child: Center(
                      child: Text(
                        entry.$2,
                        style: TextStyle(
                          fontWeight: FontWeight.w700,
                          color: active == entry.$1
                              ? Colors.white
                              : AppColors.textMuted,
                        ),
                      ),
                    ),
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
  const _SectionTitle({required this.label, required this.count});

  final String label;
  final int count;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w800,
            letterSpacing: 0.4,
          ),
        ),
        const SizedBox(width: 10),
        _Pill(
          label: '$count',
          color: Colors.white.withValues(alpha: 0.06),
          textColor: AppColors.textMuted,
          borderColor: Colors.white.withValues(alpha: 0.08),
        ),
      ],
    );
  }
}

class _DocumentCard extends StatelessWidget {
  const _DocumentCard({
    required this.doc,
    required this.isDeleting,
    required this.onDelete,
  });

  final DocumentMetadata doc;
  final bool isDeleting;
  final VoidCallback onDelete;

  String _retentionLabel() {
    final expiresAt = doc.retentionExpiresAt;
    if (expiresAt == null) return 'Follows workspace retention policy';
    final now = DateTime.now();
    final diff = expiresAt.difference(now);
    if (diff.inSeconds <= 0) return 'Scheduled for cleanup now';
    if (diff.inHours < 24) return 'Cleanup in ${diff.inHours}h';
    return 'Cleanup in ${diff.inDays} days';
  }

  String _formatDate(DateTime date) {
    final local = date.toLocal();
    return '${local.year}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [
              AppColors.surfaceDark.withValues(alpha: 0.95),
              AppColors.surfaceElevated.withValues(alpha: 0.9),
            ],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
          boxShadow: [
            BoxShadow(
              color: AppColors.primary.withValues(alpha: 0.15),
              blurRadius: 18,
              spreadRadius: 1,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  height: 48,
                  width: 48,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(14),
                    gradient: const LinearGradient(
                      colors: [AppColors.primary, AppColors.electric],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                  ),
                  child: const Icon(Icons.description_rounded, color: Colors.white),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        doc.filename,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontWeight: FontWeight.w800,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Wrap(
                        spacing: 8,
                        runSpacing: 6,
                        children: [
                          _Pill(
                            label: doc.fileType.toUpperCase(),
                            color: Colors.white.withValues(alpha: 0.04),
                            textColor: AppColors.textPrimary,
                            borderColor: Colors.white.withValues(alpha: 0.1),
                          ),
                          _Pill(
                            label: '${doc.totalChunks} chunks',
                            color: Colors.white.withValues(alpha: 0.04),
                            textColor: AppColors.textPrimary,
                            borderColor: Colors.white.withValues(alpha: 0.1),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
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
            const SizedBox(height: 10),
            Row(
              children: [
                Icon(Icons.calendar_today_rounded,
                    size: 16, color: Colors.white.withValues(alpha: 0.6)),
                const SizedBox(width: 6),
                Text(
                  _formatDate(doc.uploadedAt),
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
                const SizedBox(width: 12),
                Icon(Icons.lock_clock_rounded,
                    size: 16, color: Colors.white.withValues(alpha: 0.6)),
                const SizedBox(width: 6),
                Text(
                  _retentionLabel(),
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
                const Spacer(),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withValues(alpha: 0.16),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
                  ),
                  child: const Text(
                    'Manage',
                    style: TextStyle(
                      color: AppColors.primary,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _GenerationCard extends StatelessWidget {
  const _GenerationCard({
    required this.gen,
    required this.isDeleting,
    required this.onOpen,
    required this.onDelete,
  });

  final GenerationResponse gen;
  final bool isDeleting;
  final VoidCallback onOpen;
  final VoidCallback onDelete;

  String _formatDate(DateTime date) {
    final local = date.toLocal();
    return '${local.year}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')}';
  }

  String? _creditBucketLabel(String? bucket) {
    final norm = (bucket ?? '').trim().toLowerCase();
    switch (norm) {
      case 'task':
        return 'Task';
      case 'exam':
        return 'Exam';
      case 'legacy':
        return 'Legacy';
      case 'free':
        return 'Free';
      default:
        return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        borderRadius: BorderRadius.circular(20),
        onTap: onOpen,
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                AppColors.surfaceDark.withValues(alpha: 0.92),
                AppColors.indigo.withValues(alpha: 0.85),
              ],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: Colors.white.withValues(alpha: 0.09)),
            boxShadow: [
              BoxShadow(
                color: AppColors.accent.withValues(alpha: 0.2),
                blurRadius: 18,
                spreadRadius: 1,
                offset: const Offset(0, 12),
              ),
            ],
          ),
          child: Column(
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    height: 48,
                    width: 48,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(14),
                      gradient: const LinearGradient(
                        colors: [AppColors.accent, AppColors.electric],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                    ),
                    child: const Icon(Icons.auto_awesome_rounded, color: Colors.white),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          gen.generationType.toUpperCase(),
                          style: const TextStyle(
                            fontSize: 11,
                            letterSpacing: 1.2,
                            color: AppColors.textMuted,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          gen.content['title']?.toString().isNotEmpty == true
                              ? gen.content['title'].toString()
                              : 'Generated ${_formatDate(gen.createdAt)}',
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                            fontWeight: FontWeight.w800,
                            fontSize: 15,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          runSpacing: 6,
                          children: [
                            _Pill(
                              label: _formatDate(gen.createdAt),
                              color: Colors.white.withValues(alpha: 0.05),
                              textColor: AppColors.textPrimary,
                              borderColor: Colors.white.withValues(alpha: 0.1),
                            ),
                            if (_creditBucketLabel(gen.consumedCreditBucket) != null)
                              _Pill(
                                label: '${_creditBucketLabel(gen.consumedCreditBucket)} credit',
                                color: AppColors.primary.withValues(alpha: 0.18),
                                textColor: AppColors.primary,
                                borderColor: AppColors.primary.withValues(alpha: 0.45),
                              ),
                            if (gen.revisionCount != null && gen.revisionLimit != null)
                              _Pill(
                                label:
                                    'Revisions ${gen.revisionCount}/${gen.revisionLimit}',
                                color: Colors.white.withValues(alpha: 0.05),
                                textColor: AppColors.textPrimary,
                                borderColor: Colors.white.withValues(alpha: 0.1),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    onPressed: isDeleting ? null : onDelete,
                    icon: isDeleting
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.more_vert_rounded, color: Colors.white70),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  _GhostButton(
                    icon: Icons.visibility_rounded,
                    label: 'View',
                    onTap: onOpen,
                  ),
                  const SizedBox(width: 8),
                  _GhostButton(
                    icon: Icons.delete_outline_rounded,
                    label: 'Delete',
                    danger: true,
                    onTap: isDeleting ? null : onDelete,
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _GhostButton extends StatelessWidget {
  const _GhostButton({
    required this.icon,
    required this.label,
    this.danger = false,
    this.onTap,
  });

  final IconData icon;
  final String label;
  final bool danger;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final color = danger ? Colors.redAccent : AppColors.textPrimary;
    return Expanded(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            color: Colors.white.withValues(alpha: 0.04),
            border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  color: color,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Pill extends StatelessWidget {
  const _Pill({
    required this.label,
    required this.color,
    required this.textColor,
    required this.borderColor,
  });

  final String label;
  final Color color;
  final Color textColor;
  final Color borderColor;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: borderColor),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: textColor,
          fontSize: 11,
          fontWeight: FontWeight.w800,
          letterSpacing: 0.2,
        ),
      ),
    );
  }
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard();

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: const [
              SkeletonBox(height: 18, width: 160),
              SizedBox(height: 12),
              SkeletonBox(height: 12, width: 220),
            ],
          ),
        ),
        const SizedBox(height: 12),
        ...List.generate(
          3,
          (_) => Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: GlassContainer(
              borderRadius: 16,
              padding: const EdgeInsets.all(14),
              child: Row(
                children: const [
                  SkeletonBox(height: 42, width: 42, borderRadius: 12),
                  SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SkeletonBox(height: 14, width: 180),
                        SizedBox(height: 6),
                        SkeletonBox(height: 12, width: 120),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
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
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        color: Colors.white.withValues(alpha: 0.03),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(fontWeight: FontWeight.w800)),
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
          colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        children: const [
          Positioned(
            top: -60,
            left: -80,
            child: _GlowBlob(color: AppColors.primary, size: 260),
          ),
          Positioned(
            bottom: -80,
            right: -60,
            child: _GlowBlob(color: AppColors.accent, size: 260),
          ),
          Positioned(
            bottom: 120,
            left: 60,
            child: _GlowBlob(color: AppColors.electric, size: 180),
          ),
        ],
      ),
    );
  }
}

class _GlowBlob extends StatelessWidget {
  const _GlowBlob({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: size,
      width: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color.withValues(alpha: 0.08),
        boxShadow: [
          BoxShadow(
            color: color.withValues(alpha: 0.18),
            blurRadius: size / 2,
            spreadRadius: size / 5,
          ),
        ],
      ),
    );
  }
}

class _LibraryScreenState extends State<LibraryScreen> {
  bool _loading = true;
  bool _refreshing = false;
  bool _openingGeneration = false;
  String? _error;
  List<DocumentMetadata> _documents = [];
  List<GenerationResponse> _generations = [];
  final Set<String> _deletingDocumentIds = <String>{};
  final Set<String> _deletingGenerationIds = <String>{};
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';
  _LibrarySection _section = _LibrarySection.all;

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
    final hasData = _documents.isNotEmpty || _generations.isNotEmpty;
    setState(() {
      _loading = !hasData;
      _refreshing = hasData;
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
      setState(() {
        _error = (_documents.isEmpty && _generations.isEmpty)
            ? error.message
            : 'Unable to refresh. Showing last results.';
      });
    } catch (_) {
      setState(() {
        _error = (_documents.isEmpty && _generations.isEmpty)
            ? 'Unable to load library data.'
            : 'Unable to refresh. Showing last results.';
      });
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
          _refreshing = false;
        });
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
          builder: (_) => GenerationViewerScreen(
              generation: resolved,
              apiClient: widget.apiClient,
              session: widget.session,
              onSessionUpdated: widget.onSessionUpdated,
              onSessionInvalid: widget.onSessionInvalid,
            ),
        ),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      UiSnackbar.show(
        context,
        message: e.message,
        type: UiSnackType.error,
      );
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
      UiSnackbar.show(
        context,
        message: 'Deleted ${doc.filename}',
        type: UiSnackType.info,
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      UiSnackbar.show(
        context,
        message: e.message,
        type: UiSnackType.error,
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
      UiSnackbar.show(
        context,
        message: 'Generation deleted',
        type: UiSnackType.info,
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      UiSnackbar.show(
        context,
        message: e.message,
        type: UiSnackType.error,
      );
    } finally {
      if (mounted) {
        setState(() => _deletingGenerationIds.remove(gen.id));
      }
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final query = _searchQuery.trim().toLowerCase();
    final filteredDocs = _documents
        .where((doc) => query.isEmpty || doc.filename.toLowerCase().contains(query))
        .toList();
    final filteredGens = _generations
        .where((gen) =>
            query.isEmpty ||
            _labelForGenerationType(gen.generationType).toLowerCase().contains(query))
        .toList();
    final showDocs = _section != _LibrarySection.generations;
    final showGens = _section != _LibrarySection.documents;

    return Scaffold(
      body: Stack(
        children: [
          const UiMeshBackground(),
          SafeArea(
          child: RefreshIndicator(
            onRefresh: _loadData,
            edgeOffset: 16,
            color: AppColors.primary,
            backgroundColor: AppColors.surfaceDark,
            child: ListView(
              padding: const EdgeInsets.fromLTRB(
                AppTokens.spaceLg,
                AppTokens.spaceMd,
                AppTokens.spaceLg,
                AppTokens.spaceXl * 3.2,
              ),
              physics: const BouncingScrollPhysics(
                parent: AlwaysScrollableScrollPhysics(),
              ),
              children: [
                  _LibraryHeader(
                    name: widget.session.user.fullName.isNotEmpty
                        ? widget.session.user.fullName
                        : widget.session.user.email,
                    loading: _loading,
                    itemCount: _documents.length + _generations.length,
                  ),
                  const SizedBox(height: 14),
                  _SearchBar(
                    controller: _searchController,
                    onChanged: (value) => setState(() => _searchQuery = value),
                    onClear: () {
                      setState(() {
                        _searchQuery = '';
                        _searchController.clear();
                      });
                    },
                  ),
                  const SizedBox(height: 12),
                  _SectionChips(
                    active: _section,
                    onChanged: (next) => setState(() => _section = next),
                  ),
                  const SizedBox(height: 12),
                  if (_refreshing)
                    const GlassContainer(
                      borderRadius: 16,
                      padding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      child: Row(
                        children: [
                          SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                          SizedBox(width: 10),
                          Text('Refreshing library...', style: TextStyle(fontSize: 12)),
                        ],
                      ),
                    ),
                  if (_refreshing) const SizedBox(height: 8),
                  if (_error != null && (_documents.isNotEmpty || _generations.isNotEmpty))
                    GlassContainer(
                      borderRadius: 14,
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      child: Text(
                        _error!,
                        style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                      ),
                    ),
                  if (_error != null && (_documents.isNotEmpty || _generations.isNotEmpty))
                    const SizedBox(height: 8),
                  if (_loading && _documents.isEmpty && _generations.isEmpty)
                    const _LoadingCard(),
                  if (_error != null && _documents.isEmpty && _generations.isEmpty)
                    _ErrorCard(message: _error!),
                  if (!_loading && _error == null) ...[
                    if (showDocs) ...[
                      _SectionTitle(label: 'Documents', count: filteredDocs.length),
                      const SizedBox(height: 10),
                      if (filteredDocs.isEmpty)
                        const _EmptyState(
                          title: 'No documents yet',
                          subtitle: 'Upload PDFs, DOCX, or TXT to build your exam library.',
                        )
                      else
                        ...filteredDocs.map(
                          (doc) => _DocumentCard(
                            doc: doc,
                            isDeleting: _deletingDocumentIds.contains(doc.id),
                            onDelete: () => _deleteDocument(doc),
                          ),
                        ),
                      const SizedBox(height: 18),
                    ],
                    if (showGens) ...[
                      _SectionTitle(label: 'Recent Generations', count: filteredGens.length),
                      const SizedBox(height: 10),
                      if (filteredGens.isEmpty)
                        const _EmptyState(
                          title: 'No generations yet',
                          subtitle: 'Create exams, quizzes, or study notes to see them here.',
                        )
                      else
                        ...filteredGens.map(
                          (gen) => _GenerationCard(
                            gen: gen,
                            isDeleting: _deletingGenerationIds.contains(gen.id),
                            onOpen: () => _openGeneration(gen),
                            onDelete: () => _deleteGeneration(gen),
                          ),
                        ),
                    ],
                  ],
                  const SizedBox(height: 12),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _labelForGenerationType(String type) {
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
}


