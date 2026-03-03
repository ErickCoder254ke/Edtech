import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import '../config/app_config.dart';
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

class _JobsScreenState extends State<JobsScreen> with WidgetsBindingObserver {
  static const Duration _pollFastInterval = Duration(seconds: 3);
  static const Duration _pollSlowInterval = Duration(seconds: 20);
  static const Duration _pollResumeDelay = Duration(seconds: 1);

  bool _loading = true;
  String? _error;
  String _statusFilter = 'all';
  List<JobStatusResponse> _jobs = [];
  Timer? _pollTimer;
  Timer? _etaTicker;
  Timer? _wsReconnectTimer;
  bool _pollInFlight = false;
  WebSocket? _jobsSocket;
  bool _wsConnected = false;
  DateTime _etaNow = DateTime.now();
  DateTime? _lastJobsSyncAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _loadJobs();
    _connectJobsStream();
    _scheduleNextPoll(_pollResumeDelay);
    _startEtaTicker();
  }

  @override
  void didUpdateWidget(covariant JobsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadJobs();
      _connectJobsStream();
      _scheduleNextPoll(_pollResumeDelay);
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _connectJobsStream();
      _scheduleNextPoll(_pollResumeDelay);
      _loadJobs(silent: true);
      return;
    }
    if (state == AppLifecycleState.inactive ||
        state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _cancelPollTimer();
      _disconnectJobsStream();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _cancelPollTimer();
    _stopEtaTicker();
    _cancelWsReconnectTimer();
    _disconnectJobsStream();
    super.dispose();
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

  bool _hasActiveJobs(List<JobStatusResponse> jobs) {
    return jobs.any((job) {
      final status = job.status.toLowerCase();
      return status == 'queued' || status == 'processing' || status == 'retrying';
    });
  }

  Duration _pollIntervalForCurrentState() {
    return _hasActiveJobs(_jobs) ? _pollFastInterval : _pollSlowInterval;
  }

  void _cancelPollTimer() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  void _startEtaTicker() {
    _etaTicker?.cancel();
    _etaTicker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() => _etaNow = DateTime.now());
    });
  }

  void _stopEtaTicker() {
    _etaTicker?.cancel();
    _etaTicker = null;
  }

  void _cancelWsReconnectTimer() {
    _wsReconnectTimer?.cancel();
    _wsReconnectTimer = null;
  }

  String _joinPath(String left, String right) {
    final l = left.endsWith('/') ? left.substring(0, left.length - 1) : left;
    final r = right.startsWith('/') ? right.substring(1) : right;
    if (l.isEmpty) return '/$r';
    return '$l/$r';
  }

  Uri _buildJobsWsUri() {
    final base = Uri.parse(widget.apiClient.baseUrl);
    final prefix = AppConfig.apiPrefix;
    final withPrefix = _joinPath(base.path, prefix);
    final fullPath = _joinPath(withPrefix, '/v1/jobs/stream');
    final query = <String, String>{
      'access_token': widget.session.accessToken,
      'limit': '100',
      if (_statusFilter != 'all') 'status': _statusFilter,
    };
    return Uri(
      scheme: base.scheme == 'https' ? 'wss' : 'ws',
      host: base.host,
      port: base.hasPort ? base.port : null,
      path: fullPath,
      queryParameters: query,
    );
  }

  void _scheduleWsReconnect() {
    _cancelWsReconnectTimer();
    if (!mounted) return;
    _wsReconnectTimer = Timer(const Duration(seconds: 4), _connectJobsStream);
  }

  void _disconnectJobsStream() {
    try {
      _jobsSocket?.close(WebSocketStatus.normalClosure);
    } catch (_) {}
    _jobsSocket = null;
    _wsConnected = false;
  }

  Future<void> _connectJobsStream() async {
    if (!mounted) return;
    if (_jobsSocket != null) return;
    try {
      final ws = await WebSocket.connect(_buildJobsWsUri().toString());
      _jobsSocket = ws;
      _wsConnected = true;
      if (mounted) setState(() => _error = null);
      ws.listen(
        (data) {
          if (!mounted) return;
          try {
            final decoded = jsonDecode(data.toString());
            if (decoded is! Map<String, dynamic>) return;
            if ((decoded['type']?.toString() ?? '') != 'jobs_snapshot') return;
            final list = decoded['jobs'] as List<dynamic>? ?? const [];
            final parsed = list
                .whereType<Map<String, dynamic>>()
                .map(JobStatusResponse.fromJson)
                .toList();
            if (!mounted) return;
            setState(() {
              _jobs = parsed;
              _loading = false;
              _lastJobsSyncAt = DateTime.now();
            });
          } catch (_) {}
        },
        onDone: () {
          _jobsSocket = null;
          _wsConnected = false;
          _scheduleNextPoll(_pollResumeDelay);
          _scheduleWsReconnect();
        },
        onError: (_) {
          _jobsSocket = null;
          _wsConnected = false;
          _scheduleNextPoll(_pollResumeDelay);
          _scheduleWsReconnect();
        },
        cancelOnError: true,
      );
    } catch (_) {
      _jobsSocket = null;
      _wsConnected = false;
      _scheduleWsReconnect();
    }
  }

  void _scheduleNextPoll([Duration? delay]) {
    _cancelPollTimer();
    if (_wsConnected) return;
    if (!mounted) return;
    _pollTimer = Timer(delay ?? _pollIntervalForCurrentState(), () async {
      await _pollJobsOnce();
    });
  }

  Future<void> _pollJobsOnce() async {
    if (!mounted || _pollInFlight) {
      _scheduleNextPoll();
      return;
    }
    _pollInFlight = true;
    try {
      await _loadJobs(silent: true);
    } finally {
      _pollInFlight = false;
      if (mounted) _scheduleNextPoll();
    }
  }

  Future<void> _loadJobs({bool silent = false}) async {
    if (!silent) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    try {
      final jobs = await _runWithAuthRetry(
        (token) => widget.apiClient.listJobs(
          accessToken: token,
          limit: 100,
          status: _statusFilter == 'all' ? null : _statusFilter,
        ),
      );
      if (!mounted) return;
      setState(() {
        _jobs = jobs;
        if (!silent) _error = null;
        _lastJobsSyncAt = DateTime.now();
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      if (!silent) {
        setState(() => _error = e.message);
      }
    } catch (_) {
      if (!mounted) return;
      if (!silent) {
        setState(() => _error = 'Unable to load jobs.');
      }
    } finally {
      if (mounted && !silent) setState(() => _loading = false);
    }
  }

  int? _liveRemainingSeconds(JobStatusResponse job) {
    final base = job.estimatedRemainingSeconds;
    if (base == null) return null;
    final updatedAt = job.etaUpdatedAt;
    if (updatedAt == null) return base;
    final elapsed = _etaNow.difference(updatedAt.toLocal()).inSeconds;
    return (base - elapsed).clamp(0, 24 * 3600);
  }

  String _syncLabel() {
    final last = _lastJobsSyncAt;
    if (last == null) return _wsConnected ? 'Live connected' : 'Syncing...';
    final seconds = DateTime.now().difference(last).inSeconds.clamp(0, 3600);
    if (seconds < 2) return _wsConnected ? 'Live now' : 'Updated just now';
    return _wsConnected ? 'Live - ${seconds}s ago' : 'Polling - ${seconds}s ago';
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
                  Container(
                    margin: const EdgeInsets.only(bottom: 10),
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                    decoration: BoxDecoration(
                      color: _wsConnected
                          ? Colors.greenAccent.withValues(alpha: 0.12)
                          : Colors.amber.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(
                        color: _wsConnected
                            ? Colors.greenAccent.withValues(alpha: 0.4)
                            : Colors.amber.withValues(alpha: 0.35),
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          _wsConnected ? Icons.wifi_tethering_rounded : Icons.sync_rounded,
                          size: 16,
                          color: _wsConnected ? Colors.greenAccent : Colors.amberAccent,
                        ),
                        const SizedBox(width: 6),
                        Text(
                          _syncLabel(),
                          style: TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                            color: _wsConnected ? Colors.greenAccent : Colors.amberAccent,
                          ),
                        ),
                      ],
                    ),
                  ),
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
                                  _disconnectJobsStream();
                                  _connectJobsStream();
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
                        liveRemainingSeconds: _liveRemainingSeconds(job),
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
    required this.liveRemainingSeconds,
    required this.onOpenResult,
  });

  final JobStatusResponse job;
  final Color statusColor;
  final int? liveRemainingSeconds;
  final VoidCallback onOpenResult;

  String _formatEta(int totalSeconds) {
    final secs = totalSeconds.clamp(0, 24 * 3600);
    final minutes = secs ~/ 60;
    final seconds = secs % 60;
    if (minutes >= 60) {
      final h = minutes ~/ 60;
      final m = minutes % 60;
      return '${h}h ${m}m';
    }
    if (minutes > 0) return '${minutes}m ${seconds.toString().padLeft(2, '0')}s';
    return '${seconds}s';
  }

  String? _creditBucketLabel(String? bucket) {
    final norm = (bucket ?? '').trim().toLowerCase();
    switch (norm) {
      case 'task':
        return 'Task credit';
      case 'exam':
        return 'Exam credit';
      case 'legacy':
        return 'Legacy pack';
      case 'free':
        return 'Free tier';
      default:
        return null;
    }
  }

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
            if (job.status == 'completed' &&
                _creditBucketLabel(job.consumedCreditBucket) != null) ...[
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(999),
                  border: Border.all(
                    color: AppColors.primary.withValues(alpha: 0.35),
                  ),
                ),
                child: Text(
                  _creditBucketLabel(job.consumedCreditBucket)!,
                  style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700),
                ),
              ),
            ],
            if (liveRemainingSeconds != null &&
                (job.status == 'queued' ||
                    job.status == 'processing' ||
                    job.status == 'retrying')) ...[
              const SizedBox(height: 4),
              Text(
                'ETA: ~${_formatEta(liveRemainingSeconds!)}'
                '${job.queuePosition != null && job.status == 'queued' ? ' | Queue #${job.queuePosition}' : ''}'
                '${(job.etaConfidence ?? '').isNotEmpty ? ' | ${job.etaConfidence} confidence' : ''}',
                style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
              ),
            ],
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
