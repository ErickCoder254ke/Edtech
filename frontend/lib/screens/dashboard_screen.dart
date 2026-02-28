import 'dart:math' show max;

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onSessionUpdated,
    required this.onSessionInvalid,
    required this.onGoToUpload,
    required this.onGoToExamLab,
  });

  final ApiClient apiClient;
  final Session session;
  final ValueChanged<Session> onSessionUpdated;
  final VoidCallback onSessionInvalid;
  final VoidCallback onGoToUpload;
  final VoidCallback onGoToExamLab;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  bool _loading = true;
  String? _error;
  User? _user;
  List<DocumentMetadata> _documents = [];
  int _generationsCount = 0;
  int _documentsCount = 0;
  Map<String, dynamic>? _entitlement;

  @override
  void initState() {
    super.initState();
    _loadDashboard();
  }

  @override
  void didUpdateWidget(covariant DashboardScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadDashboard();
    }
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String token) op) async {
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

  Future<void> _loadDashboard() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final profile = _runWithAuthRetry((t) => widget.apiClient.getProfile(t));
      final overview = _runWithAuthRetry(
        (t) => widget.apiClient.getDashboardOverview(accessToken: t),
      );
      final entitlement = _runWithAuthRetry(
        (t) => widget.apiClient.subscriptionEntitlement(accessToken: t),
      );
      final results = await Future.wait<dynamic>([profile, overview, entitlement]);
      final resolvedProfile = results[0] as User;
      final resolvedOverview = results[1] as Map<String, dynamic>;
      final resolvedEntitlement = results[2] as Map<String, dynamic>;
      final recentDocsRaw = (resolvedOverview['recent_documents'] as List<dynamic>? ?? const []);
      final docs = recentDocsRaw
          .map((e) => DocumentMetadata.fromJson(e as Map<String, dynamic>))
          .toList();
      if (!mounted) return;
      setState(() {
        _user = resolvedProfile;
        _documents = docs;
        _documentsCount = (resolvedOverview['documents_count'] as num?)?.toInt() ?? docs.length;
        _generationsCount = (resolvedOverview['generations_count'] as num?)?.toInt() ?? 0;
        _entitlement = resolvedEntitlement;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Failed to load dashboard.');
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentUser = _user ?? widget.session.user;
    final docsCount = _documentsCount;
    final gensCount = _generationsCount;
    final generationLimit = (_entitlement?['generation_limit'] as num?)?.toInt() ?? 2;
    final generationUsed = (_entitlement?['generation_used_lifetime'] as num?)?.toInt() ??
        (_entitlement?['generation_used'] as num?)?.toInt() ??
        gensCount;
    final generationRemaining =
        max(0, (_entitlement?['generation_remaining'] as num?)?.toInt() ?? (generationLimit - generationUsed));
    final planName = (_entitlement?['plan_name'] as String?) ?? 'Free';
    final examLimit = (_entitlement?['exam_limit'] as num?)?.toInt();
    final examRemaining = (_entitlement?['exam_remaining'] as num?)?.toInt();
    final completionPct = generationLimit <= 0
        ? 0
        : ((generationUsed / generationLimit).clamp(0, 1) * 100).round();

    return Scaffold(
      body: Stack(
        children: [
          const _DashboardBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadDashboard,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(20, 18, 20, 120),
                children: [
                  _BrandingTile(
                    user: currentUser,
                    docsCount: docsCount,
                    generationsCount: gensCount,
                    completionPct: completionPct,
                    generationRemaining: generationRemaining,
                    generationLimit: generationLimit,
                    planName: planName,
                    examLimit: examLimit,
                    examRemaining: examRemaining,
                  ),
                  const SizedBox(height: 14),
                  if (_loading) const LinearProgressIndicator(minHeight: 3),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(_error!, style: const TextStyle(color: Colors.redAccent)),
                  ],
                  const SizedBox(height: 18),
                  const _SectionTitle('Overview'),
                  const SizedBox(height: 12),
                  _StatsGrid(
                    docsCount: docsCount,
                    gensCount: gensCount,
                    role: currentUser.role.toUpperCase(),
                    completionPct: completionPct,
                    generationRemaining: generationRemaining,
                  ),
                  const SizedBox(height: 24),
                  if (!_loading && _documentsCount == 0) ...[
                    _FirstRunCoachCard(
                      onGoToUpload: widget.onGoToUpload,
                    ),
                    const SizedBox(height: 14),
                  ],
                  if (!_loading && _documentsCount > 0 && _generationsCount == 0) ...[
                    _FirstGenerationCoachCard(
                      onGoToExamLab: widget.onGoToExamLab,
                    ),
                    const SizedBox(height: 14),
                  ],
                  const _SectionTitle('Recent Documents'),
                  const SizedBox(height: 12),
                  if (_documents.isEmpty)
                    const GlassContainer(
                      borderRadius: 18,
                      padding: EdgeInsets.all(14),
                      child: Text(
                        'No documents yet. Upload your first file in the Upload tab.',
                        style: TextStyle(color: AppColors.textMuted),
                      ),
                    )
                  else
                    ..._documents.take(4).map(
                          (doc) => Padding(
                            padding: const EdgeInsets.only(bottom: 10),
                            child: _RecentDocumentTile(doc: doc),
                          ),
                        ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _BrandingTile extends StatelessWidget {
  const _BrandingTile({
    required this.user,
    required this.docsCount,
    required this.generationsCount,
    required this.completionPct,
    required this.generationRemaining,
    required this.generationLimit,
    required this.planName,
    required this.examLimit,
    required this.examRemaining,
  });

  final User user;
  final int docsCount;
  final int generationsCount;
  final int completionPct;
  final int generationRemaining;
  final int generationLimit;
  final String planName;
  final int? examLimit;
  final int? examRemaining;

  @override
  Widget build(BuildContext context) {
    final initials = user.fullName.isEmpty
        ? 'U'
        : user.fullName
            .trim()
            .split(' ')
            .where((s) => s.isNotEmpty)
            .take(2)
            .map((e) => e[0])
            .join()
            .toUpperCase();

    return GlassContainer(
      borderRadius: 22,
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 52,
                height: 52,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: LinearGradient(
                    colors: [
                      AppColors.primary.withValues(alpha: 0.95),
                      AppColors.accent.withValues(alpha: 0.8),
                    ],
                  ),
                ),
                child: Text(
                  initials,
                  style: const TextStyle(fontWeight: FontWeight.w800),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Exam OS',
                      style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16),
                    ),
                    const SizedBox(height: 2),
                    Row(
                      children: [
                        const Text(
                          'by EdTech Intelligence',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            user.fullName.isEmpty ? user.email : user.fullName,
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.right,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _BrandTag(icon: Icons.description_outlined, text: '$docsCount Docs'),
              _BrandTag(icon: Icons.auto_awesome_rounded, text: '$generationsCount Outputs'),
              _BrandTag(
                icon: Icons.track_changes_rounded,
                text: '$planName: $generationRemaining/$generationLimit left',
              ),
              if (examLimit != null && examRemaining != null)
                _BrandTag(
                  icon: Icons.assignment_turned_in_outlined,
                  text: 'Exams: $examRemaining/$examLimit left',
                ),
            ],
          ),
          const SizedBox(height: 12),
          ClipRRect(
            borderRadius: BorderRadius.circular(10),
            child: LinearProgressIndicator(
              value: (completionPct / 100).clamp(0, 1),
              minHeight: 8,
              backgroundColor: Colors.white10,
              valueColor: const AlwaysStoppedAnimation(AppColors.primary),
            ),
          ),
        ],
      ),
    );
  }
}

class _BrandTag extends StatelessWidget {
  const _BrandTag({required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: AppColors.surfaceDark.withValues(alpha: 0.55),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.glassBorder),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: AppColors.accent),
          const SizedBox(width: 6),
          Text(text, style: const TextStyle(fontSize: 12)),
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
        fontSize: 11,
        letterSpacing: 2,
        fontWeight: FontWeight.w700,
      ),
    );
  }
}

class _StatsGrid extends StatelessWidget {
  const _StatsGrid({
    required this.docsCount,
    required this.gensCount,
    required this.role,
    required this.completionPct,
    required this.generationRemaining,
  });

  final int docsCount;
  final int gensCount;
  final String role;
  final int completionPct;
  final int generationRemaining;

  @override
  Widget build(BuildContext context) {
    final cards = [
      _MetricCardData(
        title: 'Documents',
        value: '$docsCount',
        icon: Icons.description_outlined,
      ),
      _MetricCardData(
        title: 'Generations',
        value: '$gensCount',
        icon: Icons.auto_awesome_rounded,
      ),
      _MetricCardData(
        title: 'Role',
        value: role,
        icon: Icons.badge_outlined,
      ),
      _MetricCardData(
        title: 'Remaining',
        value: '$generationRemaining',
        icon: Icons.hourglass_bottom_rounded,
      ),
      _MetricCardData(
        title: 'Progress',
        value: '$completionPct%',
        icon: Icons.track_changes_rounded,
      ),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: cards.length,
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
        childAspectRatio: 1.35,
      ),
      itemBuilder: (context, i) => _MetricCard(data: cards[i]),
    );
  }
}

class _MetricCardData {
  const _MetricCardData({
    required this.title,
    required this.value,
    required this.icon,
  });

  final String title;
  final String value;
  final IconData icon;
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({required this.data});

  final _MetricCardData data;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(data.icon, color: AppColors.primary),
          const SizedBox(height: 10),
          Flexible(
            child: FittedBox(
              fit: BoxFit.scaleDown,
              alignment: Alignment.centerLeft,
              child: Text(
                data.value,
                style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w700),
              ),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            data.title,
            style: const TextStyle(color: AppColors.textMuted),
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}

class _RecentDocumentTile extends StatelessWidget {
  const _RecentDocumentTile({required this.doc});

  final DocumentMetadata doc;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          Container(
            height: 42,
            width: 42,
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(Icons.description, color: AppColors.primary),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(doc.filename, style: const TextStyle(fontWeight: FontWeight.w700)),
                const SizedBox(height: 3),
                Text(
                  '${doc.fileType.toUpperCase()} - ${doc.totalChunks} chunks',
                  style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _DashboardBackground extends StatelessWidget {
  const _DashboardBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [AppColors.backgroundDark, Color(0xFF0F172A)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            top: 100,
            right: -110,
            child: _GlowCircle(color: AppColors.primary.withValues(alpha: 0.14)),
          ),
          Positioned(
            bottom: 150,
            left: -100,
            child: _GlowCircle(color: AppColors.accent.withValues(alpha: 0.1)),
          ),
        ],
      ),
    );
  }
}

class _FirstRunCoachCard extends StatefulWidget {
  const _FirstRunCoachCard({required this.onGoToUpload});

  final VoidCallback onGoToUpload;

  @override
  State<_FirstRunCoachCard> createState() => _FirstRunCoachCardState();
}

class _FirstRunCoachCardState extends State<_FirstRunCoachCard>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        final dy = (1 - _controller.value) * 4;
        return Transform.translate(
          offset: Offset(0, -dy),
          child: child,
        );
      },
      child: GlassContainer(
        borderRadius: 18,
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: const [
                Icon(Icons.rocket_launch_rounded, color: AppColors.accent),
                SizedBox(width: 8),
                Text(
                  'Start Here',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
                ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'You are all set. Next step: go to Upload and add your first learning document to the Exam OS engine.',
              style: TextStyle(color: AppColors.textMuted, height: 1.4),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: widget.onGoToUpload,
              icon: const Icon(Icons.upload_file_rounded),
              label: const Text('Go to Upload'),
            ),
          ],
        ),
      ),
    );
  }
}

class _FirstGenerationCoachCard extends StatelessWidget {
  const _FirstGenerationCoachCard({required this.onGoToExamLab});

  final VoidCallback onGoToExamLab;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: const [
              Icon(Icons.lightbulb_circle_rounded, color: AppColors.primary),
              SizedBox(width: 8),
              Text(
                'Generate Your First Output',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Nice. Your document is ready. Open Generation Lab to create summaries, concepts, quizzes, or a full exam.',
            style: TextStyle(color: AppColors.textMuted, height: 1.4),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: onGoToExamLab,
            icon: const Icon(Icons.auto_awesome_rounded),
            label: const Text('Open Generation Lab'),
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
      height: 240,
      width: 240,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [
          BoxShadow(color: color, blurRadius: 120, spreadRadius: 16),
        ],
      ),
    );
  }
}
