import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'generation_viewer_screen.dart';

class JobsScreen extends StatefulWidget {
  const JobsScreen({
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
  State<JobsScreen> createState() => _JobsScreenState();
}

class _JobsScreenState extends State<JobsScreen> {
  bool _loading = true;
  String? _error;
  String _statusFilter = 'all';
  List<JobStatusResponse> _jobs = [];

  @override
  void initState() {
    super.initState();
    _loadJobs();
  }

  @override
  void didUpdateWidget(covariant JobsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadJobs();
    }
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

  Future<void> _loadJobs() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final jobs = await _runWithAuthRetry(
        (token) => widget.apiClient.listJobs(
          accessToken: token,
          limit: 100,
          status: _statusFilter == 'all' ? null : _statusFilter,
        ),
      );
      if (!mounted) return;
      setState(() => _jobs = jobs);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load jobs.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Color _statusColor(String status) {
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

  Future<void> _openResult(JobStatusResponse job) async {
    if (job.resultReference == null || job.status != 'completed') return;
    try {
      final generation = await _runWithAuthRetry(
        (token) => widget.apiClient.getGeneration(
          accessToken: token,
          generationId: job.resultReference!,
        ),
      );
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => GenerationViewerScreen(generation: generation),
        ),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('My Jobs'),
        actions: [
          IconButton(
            onPressed: _loadJobs,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: Stack(
        children: [
          const _JobsBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadJobs,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
                children: [
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children:
                        ['all', 'queued', 'processing', 'completed', 'failed']
                            .map(
                              (status) => ChoiceChip(
                                label: Text(status.toUpperCase()),
                                selected: _statusFilter == status,
                                onSelected: (_) {
                                  if (_statusFilter == status) return;
                                  setState(() => _statusFilter = status);
                                  _loadJobs();
                                },
                              ),
                            )
                            .toList(),
                  ),
                  const SizedBox(height: 12),
                  if (_loading)
                    const _LoadingCard()
                  else if (_error != null)
                    _ErrorCard(message: _error!)
                  else if (_jobs.isEmpty)
                    const _EmptyCard()
                  else
                    ..._jobs.map(
                      (job) => _JobCard(
                        job: job,
                        statusColor: _statusColor(job.status),
                        onOpenResult: () => _openResult(job),
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

class _JobCard extends StatelessWidget {
  const _JobCard({
    required this.job,
    required this.statusColor,
    required this.onOpenResult,
  });

  final JobStatusResponse job;
  final Color statusColor;
  final VoidCallback onOpenResult;

  @override
  Widget build(BuildContext context) {
    final progress = (job.progress ?? 0).clamp(0, 100) / 100.0;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GlassContainer(
        borderRadius: 16,
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.tune_rounded, size: 18, color: statusColor),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '${job.type.toUpperCase()} - ${job.status.toUpperCase()}',
                    style: TextStyle(
                      fontWeight: FontWeight.w800,
                      color: statusColor,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              'Job ID: ${job.jobId}',
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
            if (job.error != null && job.error!.trim().isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(
                'Error: ${job.error}',
                style: const TextStyle(fontSize: 12, color: Colors.redAccent),
              ),
            ],
            const SizedBox(height: 8),
            LinearProgressIndicator(
              value: progress,
              minHeight: 6,
              borderRadius: BorderRadius.circular(999),
            ),
            if (job.status == 'completed' && job.resultReference != null) ...[
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: onOpenResult,
                  icon: const Icon(Icons.open_in_new_rounded),
                  label: const Text('Open Result'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard();

  @override
  Widget build(BuildContext context) {
    return const GlassContainer(
      borderRadius: 16,
      padding: EdgeInsets.all(14),
      child: Row(
        children: [
          SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          SizedBox(width: 10),
          Text('Loading jobs...'),
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
      borderRadius: 16,
      padding: const EdgeInsets.all(14),
      child: Row(
        children: [
          const Icon(Icons.error_outline, color: Colors.redAccent),
          const SizedBox(width: 10),
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

class _EmptyCard extends StatelessWidget {
  const _EmptyCard();

  @override
  Widget build(BuildContext context) {
    return const GlassContainer(
      borderRadius: 16,
      padding: EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('No jobs yet', style: TextStyle(fontWeight: FontWeight.w700)),
          SizedBox(height: 4),
          Text(
            'Queued generations will appear here for tracking.',
            style: TextStyle(color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }
}

class _JobsBackground extends StatelessWidget {
  const _JobsBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF0B1220), Color(0xFF020617)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
    );
  }
}
