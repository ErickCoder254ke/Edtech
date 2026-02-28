import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class NotificationsScreen extends StatefulWidget {
  const NotificationsScreen({
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
  State<NotificationsScreen> createState() => _NotificationsScreenState();
}

class _NotificationsScreenState extends State<NotificationsScreen> {
  bool _loading = true;
  bool _unreadOnly = false;
  String? _error;
  List<NotificationItem> _items = [];
  final Set<String> _markingRead = <String>{};

  @override
  void initState() {
    super.initState();
    _loadNotifications();
  }

  @override
  void didUpdateWidget(covariant NotificationsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadNotifications();
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

  Future<void> _loadNotifications() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final items = await _runWithAuthRetry(
        (token) => widget.apiClient.listNotifications(
          accessToken: token,
          unreadOnly: _unreadOnly,
          limit: 120,
        ),
      );
      if (!mounted) return;
      setState(() => _items = items);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load notifications.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _markRead(NotificationItem item) async {
    if (item.read || _markingRead.contains(item.id)) return;
    setState(() => _markingRead.add(item.id));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.markNotificationRead(
          accessToken: token,
          notificationId: item.id,
        ),
      );
      if (!mounted) return;
      setState(() {
        _items = _items
            .map(
              (n) => n.id == item.id
                  ? NotificationItem(
                      id: n.id,
                      userId: n.userId,
                      status: n.status,
                      message: n.message,
                      createdAt: n.createdAt,
                      read: true,
                      classId: n.classId,
                      jobId: n.jobId,
                      resultReference: n.resultReference,
                      meetingLink: n.meetingLink,
                    )
                  : n,
            )
            .toList();
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _markingRead.remove(item.id));
    }
  }

  Future<void> _openMeetingLink(NotificationItem item) async {
    final link = item.meetingLink;
    if (link == null || link.trim().isEmpty) return;
    final uri = Uri.tryParse(link);
    if (uri == null) return;
    await launchUrl(uri, mode: LaunchMode.externalApplication);
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
        title: const Text('Notifications'),
        actions: [
          IconButton(
            onPressed: _loadNotifications,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: Stack(
        children: [
          const _NotifBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadNotifications,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 24),
                children: [
                  Row(
                    children: [
                      const Text(
                        'Unread Only',
                        style: TextStyle(color: AppColors.textMuted),
                      ),
                      const SizedBox(width: 8),
                      Switch(
                        value: _unreadOnly,
                        onChanged: (v) {
                          setState(() => _unreadOnly = v);
                          _loadNotifications();
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  if (_loading)
                    const _LoadingCard()
                  else if (_error != null)
                    _ErrorCard(message: _error!)
                  else if (_items.isEmpty)
                    const _EmptyCard()
                  else
                    ..._items.map(
                      (item) => Padding(
                        padding: const EdgeInsets.only(bottom: 10),
                        child: GlassContainer(
                          borderRadius: 16,
                          padding: const EdgeInsets.all(12),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Icon(
                                    item.read
                                        ? Icons.notifications_none_rounded
                                        : Icons.notifications_active_rounded,
                                    color: item.read
                                        ? AppColors.textMuted
                                        : AppColors.accent,
                                  ),
                                  const SizedBox(width: 8),
                                  Expanded(
                                    child: Text(
                                      item.status.toUpperCase(),
                                      style: const TextStyle(
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  ),
                                  Text(
                                    _fmt(item.createdAt),
                                    style: const TextStyle(
                                      fontSize: 11,
                                      color: AppColors.textMuted,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              Text(item.message),
                              const SizedBox(height: 10),
                              Row(
                                children: [
                                  if (item.meetingLink != null &&
                                      item.meetingLink!.trim().isNotEmpty)
                                    Expanded(
                                      child: OutlinedButton.icon(
                                        onPressed: () => _openMeetingLink(item),
                                        icon: const Icon(
                                          Icons.video_call_rounded,
                                        ),
                                        label: const Text('Open Link'),
                                      ),
                                    ),
                                  if (item.meetingLink != null &&
                                      item.meetingLink!.trim().isNotEmpty)
                                    const SizedBox(width: 8),
                                  Expanded(
                                    child: OutlinedButton.icon(
                                      onPressed:
                                          item.read ||
                                              _markingRead.contains(item.id)
                                          ? null
                                          : () => _markRead(item),
                                      icon: _markingRead.contains(item.id)
                                          ? const SizedBox(
                                              width: 14,
                                              height: 14,
                                              child: CircularProgressIndicator(
                                                strokeWidth: 2,
                                              ),
                                            )
                                          : const Icon(Icons.done_rounded),
                                      label: Text(
                                        item.read ? 'Read' : 'Mark Read',
                                      ),
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
          ),
        ],
      ),
    );
  }
}

class _NotifBackground extends StatelessWidget {
  const _NotifBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF08101F), Color(0xFF050913)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
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
          Text('Loading notifications...'),
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
          Text(
            'No notifications',
            style: TextStyle(fontWeight: FontWeight.w700),
          ),
          SizedBox(height: 4),
          Text(
            'Class and generation alerts will appear here.',
            style: TextStyle(color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }
}
