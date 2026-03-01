import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class TeacherVerificationScreen extends StatefulWidget {
  const TeacherVerificationScreen({
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
  State<TeacherVerificationScreen> createState() => _TeacherVerificationScreenState();
}

class _TeacherVerificationScreenState extends State<TeacherVerificationScreen> {
  bool _loading = true;
  bool _submitting = false;
  TeacherVerification? _verification;
  List<TeacherVerificationAuditEntry> _history = const [];
  final TextEditingController _tscController = TextEditingController();
  PlatformFile? _idDoc;
  PlatformFile? _tscCert;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _tscController.dispose();
    super.dispose();
  }

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

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final data = await _runWithAuthRetry(
        (token) => widget.apiClient.getMyTeacherVerification(accessToken: token),
      );
      final history = await _runWithAuthRetry(
        (token) => widget.apiClient.getMyTeacherVerificationHistory(accessToken: token),
      );
      if (!mounted) return;
      setState(() {
        _verification = data;
        _history = history;
        if ((data.tscNumber ?? '').isNotEmpty) {
          _tscController.text = data.tscNumber!;
        }
      });
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Unable to load verification status.')),
      );
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _pickIdDoc() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: const ['pdf', 'jpg', 'jpeg', 'png'],
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    setState(() => _idDoc = result.files.first);
  }

  Future<void> _pickTscCert() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: const ['pdf', 'jpg', 'jpeg', 'png'],
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    setState(() => _tscCert = result.files.first);
  }

  Future<void> _submit() async {
    final tsc = _tscController.text.trim();
    final hasExistingId = (_verification?.idDocumentUrl ?? '').trim().isNotEmpty;
    final hasExistingTsc = (_verification?.tscCertificateUrl ?? '').trim().isNotEmpty;
    final hasId = _idDoc != null || hasExistingId;
    final hasTsc = _tscCert != null || hasExistingTsc;
    if (tsc.isEmpty || !hasId || !hasTsc) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Provide TSC number, ID and TSC certificate.')),
      );
      return;
    }
    setState(() => _submitting = true);
    try {
      final updated = await _runWithAuthRetry(
        (token) => widget.apiClient.submitTeacherVerificationFlexible(
          accessToken: token,
          tscNumber: tsc,
          idDocument: _idDoc,
          tscCertificate: _tscCert,
        ),
      );
      if (!mounted) return;
      setState(() {
        _verification = updated;
        _idDoc = null;
        _tscCert = null;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Verification submitted for admin review.')),
      );
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _openLink(String? link) async {
    final raw = (link ?? '').trim();
    if (raw.isEmpty) return;
    final uri = _buildPreviewUri(raw);
    if (uri == null) return;
    final opened = await launchUrl(uri, mode: LaunchMode.inAppBrowserView);
    if (!opened) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  Uri? _buildPreviewUri(String rawUrl) {
    final parsed = Uri.tryParse(rawUrl);
    if (parsed == null) return null;
    final looksPdf =
        parsed.path.toLowerCase().endsWith('.pdf') ||
        rawUrl.toLowerCase().contains('.pdf?');
    if (!looksPdf) return parsed;
    return Uri.parse(
      'https://docs.google.com/gview?embedded=1&url=${Uri.encodeComponent(rawUrl)}',
    );
  }

  @override
  Widget build(BuildContext context) {
    final status = _verification?.status ?? 'not_submitted';
    final isApproved = status == 'approved';
    final isPending = status == 'pending';
    final isRejected = status == 'rejected';
    return Scaffold(
      appBar: AppBar(title: const Text('Teacher Verification')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                GlassContainer(
                  borderRadius: 16,
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Status: ${status.toUpperCase()}',
                        style: TextStyle(
                          fontWeight: FontWeight.w700,
                          color: isApproved
                              ? Colors.greenAccent
                              : isRejected
                                  ? Colors.redAccent
                                  : AppColors.accent,
                        ),
                      ),
                      if ((_verification?.reviewComment ?? '').isNotEmpty) ...[
                        const SizedBox(height: 8),
                        Text('Admin comment: ${_verification!.reviewComment}'),
                      ],
                      if (isApproved) ...[
                        const SizedBox(height: 10),
                        const Text(
                          'You are verified and can now create classes.',
                          style: TextStyle(color: Colors.greenAccent),
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                if (!isApproved)
                  GlassContainer(
                    borderRadius: 16,
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        TextField(
                          controller: _tscController,
                          decoration: const InputDecoration(labelText: 'TSC registration number'),
                        ),
                        const SizedBox(height: 10),
                        OutlinedButton.icon(
                          onPressed: _pickIdDoc,
                          icon: const Icon(Icons.badge_rounded),
                          label: Text(
                            _idDoc == null
                                ? 'Upload ID document'
                                : 'ID: ${_idDoc!.name}',
                          ),
                        ),
                        if ((_verification?.idDocumentUrl ?? '').isNotEmpty)
                          TextButton(
                            onPressed: () => _openLink(_verification?.idDocumentUrl),
                            child: const Text('View current ID document'),
                          ),
                        const SizedBox(height: 8),
                        OutlinedButton.icon(
                          onPressed: _pickTscCert,
                          icon: const Icon(Icons.verified_rounded),
                          label: Text(
                            _tscCert == null
                                ? 'Upload TSC certificate'
                                : 'TSC: ${_tscCert!.name}',
                          ),
                        ),
                        if ((_verification?.tscCertificateUrl ?? '').isNotEmpty)
                          TextButton(
                            onPressed: () => _openLink(_verification?.tscCertificateUrl),
                            child: const Text('View current TSC certificate'),
                          ),
                        const SizedBox(height: 12),
                        SizedBox(
                          width: double.infinity,
                          child: FilledButton(
                            onPressed: (_submitting || isPending) ? null : _submit,
                            child: Text(
                              isPending
                                  ? 'Under Review'
                                  : (_submitting ? 'Submitting...' : 'Submit Verification'),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                const SizedBox(height: 12),
                GlassContainer(
                  borderRadius: 16,
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Verification History',
                        style: TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const SizedBox(height: 8),
                      if (_history.isEmpty)
                        const Text(
                          'No history yet.',
                          style: TextStyle(color: AppColors.textMuted),
                        )
                      else
                        ..._history.map(
                          (e) => Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  '${e.action.toUpperCase()} by ${e.actorRole}',
                                  style: const TextStyle(fontWeight: FontWeight.w700),
                                ),
                                Text(
                                  e.at.toLocal().toString(),
                                  style: const TextStyle(
                                    fontSize: 12,
                                    color: AppColors.textMuted,
                                  ),
                                ),
                                if ((e.comment ?? '').isNotEmpty) Text(e.comment!),
                              ],
                            ),
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
