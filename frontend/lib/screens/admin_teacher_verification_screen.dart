import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class AdminTeacherVerificationScreen extends StatefulWidget {
  const AdminTeacherVerificationScreen({
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
  State<AdminTeacherVerificationScreen> createState() => _AdminTeacherVerificationScreenState();
}

class _AdminTeacherVerificationScreenState extends State<AdminTeacherVerificationScreen> {
  bool _loading = true;
  String _status = 'pending';
  List<TeacherVerification> _items = const [];

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String token) op) async {
    try {
      return await op(widget.session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      final refreshed = await widget.apiClient.refreshTokens(
        refreshToken: widget.session.refreshToken,
      );
      final next = refreshed.toSession();
      widget.onSessionUpdated(next);
      return op(next.accessToken);
    }
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final data = await _runWithAuthRetry(
        (token) => widget.apiClient.listTeacherVerifications(
          accessToken: token,
          status: _status,
          limit: 120,
        ),
      );
      if (!mounted) return;
      setState(() => _items = data);
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _review(TeacherVerification item, String action) async {
    final controller = TextEditingController();
    final comment = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(action == 'approve' ? 'Approve Teacher' : 'Reject Teacher'),
        content: TextField(
          controller: controller,
          minLines: 2,
          maxLines: 4,
          decoration: const InputDecoration(
            labelText: 'Comment (visible to teacher)',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
            child: const Text('Submit'),
          ),
        ],
      ),
    );
    if (comment == null) return;
    if (action == 'reject' && comment.trim().isEmpty) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Rejection comment is required.')),
      );
      return;
    }
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.reviewTeacherVerification(
          accessToken: token,
          teacherId: item.teacherId,
          action: action,
          comment: comment,
        ),
      );
      if (!mounted) return;
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Future<void> _openLink(String? link) async {
    final raw = (link ?? '').trim();
    if (raw.isEmpty) return;
    final uri = Uri.tryParse(raw);
    if (uri == null) return;
    await launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  bool _isImageUrl(String? link) {
    final raw = (link ?? '').toLowerCase();
    return raw.endsWith('.png') ||
        raw.endsWith('.jpg') ||
        raw.endsWith('.jpeg') ||
        raw.endsWith('.webp');
  }

  Future<void> _previewDocument(String? link, String title) async {
    if ((link ?? '').trim().isEmpty) return;
    if (!_isImageUrl(link)) {
      await _openLink(link);
      return;
    }
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 520,
          child: InteractiveViewer(
            child: Image.network(link!, fit: BoxFit.contain),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => _openLink(link),
            child: const Text('Open External'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _showHistory(TeacherVerification item) async {
    try {
      final entries = await _runWithAuthRetry(
        (token) => widget.apiClient.getTeacherVerificationHistory(
          accessToken: token,
          teacherId: item.teacherId,
        ),
      );
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Verification Audit History'),
          content: SizedBox(
            width: 520,
            child: entries.isEmpty
                ? const Text('No audit events yet.')
                : ListView.separated(
                    shrinkWrap: true,
                    itemCount: entries.length,
                    separatorBuilder: (_, __) => const Divider(height: 16),
                    itemBuilder: (_, index) {
                      final e = entries[index];
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            '${e.action.toUpperCase()} by ${e.actorRole}',
                            style: const TextStyle(fontWeight: FontWeight.w700),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            e.at.toLocal().toString(),
                            style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                          ),
                          if ((e.comment ?? '').isNotEmpty) ...[
                            const SizedBox(height: 4),
                            Text(e.comment!),
                          ],
                        ],
                      );
                    },
                  ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Teacher Verification Review'),
        actions: [
          DropdownButton<String>(
            value: _status,
            underline: const SizedBox.shrink(),
            items: const [
              DropdownMenuItem(value: 'pending', child: Text('Pending')),
              DropdownMenuItem(value: 'approved', child: Text('Approved')),
              DropdownMenuItem(value: 'rejected', child: Text('Rejected')),
              DropdownMenuItem(value: 'all', child: Text('All')),
            ],
            onChanged: (value) {
              if (value == null) return;
              setState(() => _status = value);
              _load();
            },
          ),
          IconButton(
            onPressed: _load,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: _items.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (_, index) {
                final item = _items[index];
                return GlassContainer(
                  borderRadius: 14,
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Teacher ID: ${item.teacherId}',
                        style: const TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const SizedBox(height: 4),
                      Text('Status: ${item.status} | TSC: ${item.tscNumber ?? '-'}'),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          if ((item.idDocumentUrl ?? '').isNotEmpty)
                            OutlinedButton.icon(
                              onPressed: () =>
                                  _previewDocument(item.idDocumentUrl, 'ID Document'),
                              icon: const Icon(Icons.badge_rounded, size: 16),
                              label: const Text('Open ID'),
                            ),
                          if ((item.tscCertificateUrl ?? '').isNotEmpty)
                            OutlinedButton.icon(
                              onPressed: () => _previewDocument(
                                item.tscCertificateUrl,
                                'TSC Certificate',
                              ),
                              icon: const Icon(Icons.verified_rounded, size: 16),
                              label: const Text('Open TSC Cert'),
                            ),
                          OutlinedButton.icon(
                            onPressed: () => _showHistory(item),
                            icon: const Icon(Icons.history_rounded, size: 16),
                            label: const Text('Audit Trail'),
                          ),
                        ],
                      ),
                      if (item.status == 'pending') ...[
                        const SizedBox(height: 10),
                        Row(
                          children: [
                            Expanded(
                              child: FilledButton(
                                onPressed: () => _review(item, 'approve'),
                                child: const Text('Approve'),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: OutlinedButton(
                                onPressed: () => _review(item, 'reject'),
                                child: const Text('Reject'),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ],
                  ),
                );
              },
            ),
    );
  }
}
