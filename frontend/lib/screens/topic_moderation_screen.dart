import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class TopicModerationScreen extends StatefulWidget {
  const TopicModerationScreen({
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
  State<TopicModerationScreen> createState() => _TopicModerationScreenState();
}

class _TopicModerationScreenState extends State<TopicModerationScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;
  bool _loading = true;
  String? _error;
  List<TopicAbuseEvent> _events = [];
  List<TopicFlaggedItem> _flagged = [];
  final Set<String> _resolving = <String>{};

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _load();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
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

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final events = await _runWithAuthRetry(
        (token) => widget.apiClient.listTopicAbuseEvents(accessToken: token),
      );
      final flagged = await _runWithAuthRetry(
        (token) => widget.apiClient.listFlaggedTopics(accessToken: token),
      );
      if (!mounted) return;
      setState(() {
        _events = events;
        _flagged = flagged;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Failed to load topic moderation data.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _resolve(String topicId) async {
    if (_resolving.contains(topicId)) return;
    setState(() => _resolving.add(topicId));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.resolveFlaggedTopic(
          accessToken: token,
          topicId: topicId,
        ),
      );
      if (!mounted) return;
      setState(() {
        _flagged = _flagged.where((item) => item.id != topicId).toList();
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Flag resolved.')),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    } finally {
      if (mounted) setState(() => _resolving.remove(topicId));
    }
  }

  String _fmt(DateTime dt) {
    final l = dt.toLocal();
    final y = l.year.toString().padLeft(4, '0');
    final m = l.month.toString().padLeft(2, '0');
    final d = l.day.toString().padLeft(2, '0');
    final hh = l.hour.toString().padLeft(2, '0');
    final mm = l.minute.toString().padLeft(2, '0');
    return '$y-$m-$d $hh:$mm';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Topic Moderation'),
        actions: [
          IconButton(
            onPressed: _load,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'Flagged Topics'),
            Tab(text: 'Abuse Events'),
          ],
        ),
      ),
      body: Stack(
        children: [
          Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFF0A1020), Color(0xFF050913)],
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
              ),
            ),
          ),
          if (_loading)
            const Center(child: CircularProgressIndicator())
          else if (_error != null)
            Center(
              child: GlassContainer(
                borderRadius: 16,
                padding: const EdgeInsets.all(14),
                child: Text(_error!, style: const TextStyle(color: Colors.redAccent)),
              ),
            )
          else
            TabBarView(
              controller: _tabController,
              children: [
                ListView(
                  padding: const EdgeInsets.all(14),
                  children: _flagged.isEmpty
                      ? [
                          const GlassContainer(
                            borderRadius: 16,
                            padding: EdgeInsets.all(14),
                            child: Text('No flagged topics right now.'),
                          ),
                        ]
                      : _flagged
                            .map(
                              (item) => Padding(
                                padding: const EdgeInsets.only(bottom: 10),
                                child: GlassContainer(
                                  borderRadius: 16,
                                  padding: const EdgeInsets.all(12),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(item.title, style: const TextStyle(fontWeight: FontWeight.w800)),
                                      const SizedBox(height: 6),
                                      Text(
                                        '${item.categoryLabel} • ${item.upvoteCount} votes',
                                        style: const TextStyle(color: AppColors.textMuted),
                                      ),
                                      if (item.fraudSpikeFlaggedAt != null) ...[
                                        const SizedBox(height: 4),
                                        Text(
                                          'Flagged: ${_fmt(item.fraudSpikeFlaggedAt!)}',
                                          style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                                        ),
                                      ],
                                      const SizedBox(height: 10),
                                      Align(
                                        alignment: Alignment.centerRight,
                                        child: FilledButton.icon(
                                          onPressed: _resolving.contains(item.id)
                                              ? null
                                              : () => _resolve(item.id),
                                          icon: _resolving.contains(item.id)
                                              ? const SizedBox(
                                                  width: 14,
                                                  height: 14,
                                                  child: CircularProgressIndicator(strokeWidth: 2),
                                                )
                                              : const Icon(Icons.verified_rounded),
                                          label: const Text('Resolve'),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            )
                            .toList(),
                ),
                ListView(
                  padding: const EdgeInsets.all(14),
                  children: _events.isEmpty
                      ? [
                          const GlassContainer(
                            borderRadius: 16,
                            padding: EdgeInsets.all(14),
                            child: Text('No abuse events logged.'),
                          ),
                        ]
                      : _events
                            .map(
                              (event) => Padding(
                                padding: const EdgeInsets.only(bottom: 10),
                                child: GlassContainer(
                                  borderRadius: 16,
                                  padding: const EdgeInsets.all(12),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        event.eventType,
                                        style: const TextStyle(fontWeight: FontWeight.w700),
                                      ),
                                      const SizedBox(height: 6),
                                      Text(
                                        'User: ${event.userId}',
                                        style: const TextStyle(color: AppColors.textMuted),
                                      ),
                                      if ((event.suggestionId ?? '').isNotEmpty)
                                        Text(
                                          'Topic: ${event.suggestionId}',
                                          style: const TextStyle(color: AppColors.textMuted),
                                        ),
                                      if ((event.ipAddress ?? '').isNotEmpty)
                                        Text(
                                          'IP: ${event.ipAddress}',
                                          style: const TextStyle(color: AppColors.textMuted),
                                        ),
                                      const SizedBox(height: 4),
                                      Text(
                                        _fmt(event.createdAt),
                                        style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            )
                            .toList(),
                ),
              ],
            ),
        ],
      ),
    );
  }
}
