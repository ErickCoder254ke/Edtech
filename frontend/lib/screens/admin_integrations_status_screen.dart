import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class AdminIntegrationsStatusScreen extends StatefulWidget {
  const AdminIntegrationsStatusScreen({
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
  State<AdminIntegrationsStatusScreen> createState() => _AdminIntegrationsStatusScreenState();
}

class _AdminIntegrationsStatusScreenState extends State<AdminIntegrationsStatusScreen> {
  bool _loading = true;
  String? _error;
  Map<String, dynamic> _status = const {};

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
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final data = await _runWithAuthRetry(
        (token) => widget.apiClient.getAdminIntegrationStatus(accessToken: token),
      );
      if (!mounted) return;
      setState(() => _status = data);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load integration status.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Widget _tile({
    required String title,
    required Map<String, dynamic> payload,
  }) {
    return GlassContainer(
      borderRadius: 14,
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(fontWeight: FontWeight.w800)),
          const SizedBox(height: 8),
          ...payload.entries.map(
            (e) => Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                '${e.key}: ${e.value}',
                style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final localpro = (_status['localpro'] as Map<String, dynamic>?) ?? const {};
    final firebase = (_status['firebase'] as Map<String, dynamic>?) ?? const {};
    final brevo = (_status['brevo'] as Map<String, dynamic>?) ?? const {};
    final queue = (_status['queue'] as Map<String, dynamic>?) ?? const {};

    return Scaffold(
      appBar: AppBar(
        title: const Text('Integration Status'),
        actions: [IconButton(onPressed: _load, icon: const Icon(Icons.refresh_rounded))],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
              ? Center(child: Text(_error!))
              : ListView(
                  padding: const EdgeInsets.all(16),
                  children: [
                    _tile(title: 'LocalPro', payload: localpro),
                    const SizedBox(height: 10),
                    _tile(title: 'Firebase', payload: firebase),
                    const SizedBox(height: 10),
                    _tile(title: 'Brevo', payload: brevo),
                    const SizedBox(height: 10),
                    _tile(title: 'Queue / Delivery', payload: queue),
                  ],
                ),
    );
  }
}

