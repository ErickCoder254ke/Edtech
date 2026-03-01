import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'admin_integrations_status_screen.dart';
import 'admin_teacher_verification_screen.dart';

class AdminDashboardScreen extends StatefulWidget {
  const AdminDashboardScreen({
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
  State<AdminDashboardScreen> createState() => _AdminDashboardScreenState();
}

class _AdminDashboardScreenState extends State<AdminDashboardScreen> {
  bool _loading = true;
  bool _savingSettings = false;
  bool _submittingWithdrawal = false;
  String? _error;
  AdminDashboardSummary? _summary;
  AdminRuntimeSettings? _runtimeSettings;
  Map<String, dynamic> _integrationStatus = const {};
  Map<String, Map<String, dynamic>> _acknowledgedAlerts = const <String, Map<String, dynamic>>{};

  final TextEditingController _subscriptionWeeklyKesController =
      TextEditingController();
  final TextEditingController _subscriptionMonthlyKesController =
      TextEditingController();
  final TextEditingController _subscriptionAnnualKesController =
      TextEditingController();
  final TextEditingController _weeklyPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _monthlyPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _annualPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _classEscrowPlatformFeePercentController =
      TextEditingController();
  final TextEditingController _classMinFeeKesController =
      TextEditingController();
  final TextEditingController _classMaxFeeKesController =
      TextEditingController();
  final TextEditingController _accountReuseGraceDaysController =
      TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
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

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final results = await Future.wait<dynamic>([
        _runWithAuthRetry(
          (token) =>
              widget.apiClient.getAdminDashboardSummary(accessToken: token),
        ),
        _runWithAuthRetry(
          (token) =>
              widget.apiClient.getAdminRuntimeSettings(accessToken: token),
        ),
        _runWithAuthRetry(
          (token) =>
              widget.apiClient.getAdminIntegrationStatus(accessToken: token),
        ),
        _runWithAuthRetry(
          (token) =>
              widget.apiClient.getAdminAlertAcknowledgements(accessToken: token),
        ),
      ]);
      final summary = results[0] as AdminDashboardSummary;
      final runtimeSettings = results[1] as AdminRuntimeSettings;
      final integrationStatus = results[2] as Map<String, dynamic>;
      final acknowledged = results[3] as Map<String, Map<String, dynamic>>;
      if (!mounted) return;
      setState(() {
        _summary = summary;
        _runtimeSettings = runtimeSettings;
        _integrationStatus = integrationStatus;
        _acknowledgedAlerts = acknowledged;
      });
      _hydrateSettingsControllers(runtimeSettings);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load admin dashboard.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _openAdminIntegrationsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AdminIntegrationsStatusScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onSessionInvalid,
        ),
      ),
    );
  }

  void _openAdminTeacherVerificationsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AdminTeacherVerificationScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onSessionInvalid,
        ),
      ),
    );
  }

  List<_SystemAlert> _buildSystemAlerts() {
    final localpro = (_integrationStatus['localpro'] as Map<String, dynamic>?) ?? const {};
    final firebase = (_integrationStatus['firebase'] as Map<String, dynamic>?) ?? const {};
    final brevo = (_integrationStatus['brevo'] as Map<String, dynamic>?) ?? const {};
    final queue = (_integrationStatus['queue'] as Map<String, dynamic>?) ?? const {};

    final alerts = <_SystemAlert>[];

    final localproConfigured = localpro['configured'] == true;
    final localproError = (localpro['last_fetch_error'] ?? '').toString().trim();
    if (!localproConfigured) {
      alerts.add(
        const _SystemAlert(
          key: 'localpro_not_configured',
          level: _AlertLevel.warning,
          title: 'LocalPro not configured',
          detail: 'Set LOCALPRO_BASE_URL and API key to enable private tutor listing.',
        ),
      );
    } else if (localproError.isNotEmpty) {
      alerts.add(
        _SystemAlert(
          key: 'localpro_fetch_failed',
          level: _AlertLevel.critical,
          title: 'LocalPro fetch failing',
          detail: localproError,
        ),
      );
    }

    if (queue['redis_ping_ok'] != true) {
      alerts.add(
        _SystemAlert(
          key: 'redis_ping_failed',
          level: _AlertLevel.critical,
          title: 'Queue Redis ping failed',
          detail: (queue['redis_error'] ?? 'Unknown Redis error').toString(),
        ),
      );
    }

    if (firebase['enabled'] == true && firebase['ready'] != true) {
      alerts.add(
        const _SystemAlert(
          key: 'firebase_not_ready',
          level: _AlertLevel.warning,
          title: 'Firebase not ready',
          detail: 'Push notifications may not be delivered.',
        ),
      );
    }

    final emailsFailed = (brevo['emails_failed_24h'] as num?)?.toInt() ?? 0;
    if (emailsFailed > 20) {
      alerts.add(
        _SystemAlert(
          key: 'brevo_high_failures',
          level: _AlertLevel.warning,
          title: 'High email failures',
          detail: '$emailsFailed Brevo email sends failed in the last 24h.',
        ),
      );
    }

    final failedGen = (queue['generation_failed_24h'] as num?)?.toInt() ?? 0;
    final completedGen = (queue['generation_completed_24h'] as num?)?.toInt() ?? 0;
    final ratio = failedGen / (completedGen == 0 ? 1 : completedGen);
    if (failedGen >= 10 && ratio > 0.2) {
      alerts.add(
        _SystemAlert(
          key: 'generation_failure_spike',
          level: _AlertLevel.warning,
          title: 'Generation failures elevated',
          detail:
              'Failed: $failedGen, Completed: $completedGen in 24h. Investigate AI providers/queue.',
        ),
      );
    }

    if (alerts.isEmpty) {
      alerts.add(
        const _SystemAlert(
          key: 'system_ok',
          level: _AlertLevel.ok,
          title: 'All core integrations healthy',
          detail: 'No critical warnings detected in the latest snapshot.',
        ),
      );
    }
    return alerts
        .map(
          (a) => a.copyWith(
            acknowledged: _acknowledgedAlerts.containsKey(a.key),
            acknowledgedBy: _acknowledgedAlerts[a.key]?['acknowledged_by']?.toString(),
            acknowledgedAt: _acknowledgedAlerts[a.key]?['acknowledged_at']?.toString(),
          ),
        )
        .toList();
  }

  Future<void> _toggleAlertAcknowledgement(_SystemAlert alert) async {
    try {
      if (alert.acknowledged) {
        await _runWithAuthRetry(
          (token) => widget.apiClient.unacknowledgeAdminAlert(
            accessToken: token,
            alertKey: alert.key,
          ),
        );
      } else {
        await _runWithAuthRetry(
          (token) => widget.apiClient.acknowledgeAdminAlert(
            accessToken: token,
            alertKey: alert.key,
          ),
        );
      }
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    }
  }

  void _hydrateSettingsControllers(AdminRuntimeSettings settings) {
    _subscriptionWeeklyKesController.text = settings.subscriptionWeeklyKes
        .toString();
    _subscriptionMonthlyKesController.text = settings.subscriptionMonthlyKes
        .toString();
    _subscriptionAnnualKesController.text = settings.subscriptionAnnualKes
        .toString();
    _weeklyPlanMaxExamsController.text = settings.weeklyPlanMaxExams.toString();
    _monthlyPlanMaxExamsController.text = settings.monthlyPlanMaxExams
        .toString();
    _annualPlanMaxExamsController.text = settings.annualPlanMaxExams.toString();
    _classEscrowPlatformFeePercentController.text = settings
        .classEscrowPlatformFeePercent
        .toString();
    _classMinFeeKesController.text = settings.classMinFeeKes.toString();
    _classMaxFeeKesController.text = settings.classMaxFeeKes.toString();
    _accountReuseGraceDaysController.text = settings.accountReuseGraceDays
        .toString();
  }

  Future<void> _saveRuntimeSettings() async {
    final payload = <String, dynamic>{
      'subscription_weekly_kes': int.tryParse(
        _subscriptionWeeklyKesController.text.trim(),
      ),
      'subscription_monthly_kes': int.tryParse(
        _subscriptionMonthlyKesController.text.trim(),
      ),
      'subscription_annual_kes': int.tryParse(
        _subscriptionAnnualKesController.text.trim(),
      ),
      'weekly_plan_max_exams': int.tryParse(
        _weeklyPlanMaxExamsController.text.trim(),
      ),
      'monthly_plan_max_exams': int.tryParse(
        _monthlyPlanMaxExamsController.text.trim(),
      ),
      'annual_plan_max_exams': int.tryParse(
        _annualPlanMaxExamsController.text.trim(),
      ),
      'class_escrow_platform_fee_percent': double.tryParse(
        _classEscrowPlatformFeePercentController.text.trim(),
      ),
      'class_min_fee_kes': int.tryParse(_classMinFeeKesController.text.trim()),
      'class_max_fee_kes': int.tryParse(_classMaxFeeKesController.text.trim()),
      'account_reuse_grace_days': int.tryParse(
        _accountReuseGraceDaysController.text.trim(),
      ),
    }..removeWhere((_, value) => value == null);

    if (payload.length != 10) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter valid values for all settings.'),
        ),
      );
      return;
    }

    setState(() => _savingSettings = true);
    try {
      final settings = await _runWithAuthRetry(
        (token) => widget.apiClient.updateAdminRuntimeSettings(
          accessToken: token,
          settings: payload,
        ),
      );
      if (!mounted) return;
      setState(() => _runtimeSettings = settings);
      _hydrateSettingsControllers(settings);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Runtime settings updated.')),
      );
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _savingSettings = false);
    }
  }

  Future<void> _openWithdrawalDialog() async {
    final amountController = TextEditingController();
    final phoneController = TextEditingController();
    final noteController = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Initiate Platform Withdrawal'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: amountController,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(hintText: 'Amount (KES)'),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: phoneController,
              keyboardType: TextInputType.phone,
              decoration: const InputDecoration(
                hintText: 'Phone number (optional)',
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: noteController,
              maxLines: 2,
              decoration: const InputDecoration(hintText: 'Note (optional)'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Submit'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    final amount = int.tryParse(amountController.text.trim()) ?? 0;
    if (amount <= 0) return;

    setState(() => _submittingWithdrawal = true);
    try {
      final result = await _runWithAuthRetry(
        (token) => widget.apiClient.requestPlatformWithdrawal(
          accessToken: token,
          amountKes: amount,
          phoneNumber: phoneController.text.trim().isEmpty
              ? null
              : phoneController.text.trim(),
          note: noteController.text.trim().isEmpty
              ? null
              : noteController.text.trim(),
        ),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            result['message']?.toString() ?? 'Withdrawal requested.',
          ),
        ),
      );
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _submittingWithdrawal = false);
    }
  }

  Widget _metricTile(String label, String value, {IconData? icon}) {
    return GlassContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          if (icon != null) ...[
            Icon(icon, color: AppColors.primary),
            const SizedBox(width: 8),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: const TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 17,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _settingsField(
    String label,
    TextEditingController controller, {
    String? hint,
    TextInputType keyboardType = TextInputType.number,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: TextField(
        controller: controller,
        keyboardType: keyboardType,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _subscriptionWeeklyKesController.dispose();
    _subscriptionMonthlyKesController.dispose();
    _subscriptionAnnualKesController.dispose();
    _weeklyPlanMaxExamsController.dispose();
    _monthlyPlanMaxExamsController.dispose();
    _annualPlanMaxExamsController.dispose();
    _classEscrowPlatformFeePercentController.dispose();
    _classMinFeeKesController.dispose();
    _classMaxFeeKesController.dispose();
    _accountReuseGraceDaysController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final summary = _summary;
    final runtimeSettings = _runtimeSettings;
    final alerts = _buildSystemAlerts();
    return Scaffold(
      appBar: AppBar(
        title: const Text('Admin Dashboard'),
        actions: [
          IconButton(onPressed: _load, icon: const Icon(Icons.refresh_rounded)),
        ],
      ),
      body: Stack(
        children: [
          Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFF071020), Color(0xFF0B0D1A)],
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
                child: Text(
                  _error!,
                  style: const TextStyle(color: Colors.redAccent),
                ),
              ),
            )
          else if (summary == null || runtimeSettings == null)
            const Center(child: Text('No data available'))
          else
            ListView(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
              children: [
                _metricTile(
                  'Platform Wallet Balance',
                  'KES ${summary.platformWalletBalanceKes}',
                  icon: Icons.account_balance_wallet_rounded,
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: _metricTile(
                        'Total Earned',
                        'KES ${summary.platformWalletTotalEarnedKes}',
                        icon: Icons.trending_up_rounded,
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: _metricTile(
                        'Total Withdrawn',
                        'KES ${summary.platformWalletTotalWithdrawnKes}',
                        icon: Icons.call_made_rounded,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                _metricTile(
                  'Users Total',
                  '${summary.usersTotal}',
                  icon: Icons.groups_rounded,
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: _metricTile(
                        'Students',
                        '${summary.studentsCount}',
                        icon: Icons.school_rounded,
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: _metricTile(
                        'Teachers',
                        '${summary.teachersCount}',
                        icon: Icons.menu_book_rounded,
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: _metricTile(
                        'Admins',
                        '${summary.adminsCount}',
                        icon: Icons.admin_panel_settings_rounded,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                GlassContainer(
                  borderRadius: 16,
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'System Alerts',
                        style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16),
                      ),
                      const SizedBox(height: 8),
                      ...alerts.map(
                        (alert) => Container(
                          margin: const EdgeInsets.only(bottom: 8),
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: alert.level == _AlertLevel.critical
                                ? Colors.red.withValues(alpha: 0.14)
                                : alert.level == _AlertLevel.warning
                                    ? Colors.orange.withValues(alpha: 0.14)
                                    : Colors.green.withValues(alpha: 0.14),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: alert.level == _AlertLevel.critical
                                  ? Colors.redAccent.withValues(alpha: 0.35)
                                  : alert.level == _AlertLevel.warning
                                      ? Colors.orangeAccent.withValues(alpha: 0.35)
                                      : Colors.greenAccent.withValues(alpha: 0.35),
                            ),
                          ),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Icon(
                                alert.level == _AlertLevel.critical
                                    ? Icons.error_rounded
                                    : alert.level == _AlertLevel.warning
                                        ? Icons.warning_rounded
                                        : Icons.check_circle_rounded,
                                color: alert.level == _AlertLevel.ok
                                    ? Colors.greenAccent
                                    : Colors.orangeAccent,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      alert.title,
                                      style: const TextStyle(fontWeight: FontWeight.w700),
                                    ),
                                    const SizedBox(height: 2),
                                    Text(
                                      alert.detail,
                                      style: const TextStyle(
                                        fontSize: 12,
                                        color: AppColors.textMuted,
                                      ),
                                    ),
                                    if (alert.acknowledged &&
                                        (alert.acknowledgedBy != null ||
                                            alert.acknowledgedAt != null)) ...[
                                      const SizedBox(height: 4),
                                      Text(
                                        'Reviewed by ${alert.acknowledgedBy ?? "-"}'
                                        '${alert.acknowledgedAt != null ? " at ${alert.acknowledgedAt}" : ""}',
                                        style: const TextStyle(
                                          fontSize: 11,
                                          color: AppColors.textMuted,
                                        ),
                                      ),
                                    ],
                                  ],
                                ),
                              ),
                              if (alert.level != _AlertLevel.ok)
                                TextButton(
                                  onPressed: () => _toggleAlertAcknowledgement(alert),
                                  child: Text(
                                    alert.acknowledged ? 'Reviewed' : 'Mark Reviewed',
                                  ),
                                ),
                            ],
                          ),
                        ),
                      ),
                      const SizedBox(height: 6),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          OutlinedButton.icon(
                            onPressed: _openAdminIntegrationsPage,
                            icon: const Icon(Icons.hub_rounded, size: 16),
                            label: const Text('Open Integrations'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _openAdminTeacherVerificationsPage,
                            icon: const Icon(Icons.fact_check_rounded, size: 16),
                            label: const Text('Open Teacher Verifications'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _load,
                            icon: const Icon(Icons.refresh_rounded, size: 16),
                            label: const Text('Retry Health Check'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                FilledButton.icon(
                  onPressed: _submittingWithdrawal
                      ? null
                      : _openWithdrawalDialog,
                  icon: _submittingWithdrawal
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.payments_outlined),
                  label: const Text('Initiate Platform Withdrawal'),
                ),
                const SizedBox(height: 18),
                GlassContainer(
                  borderRadius: 16,
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Runtime Settings',
                        style: TextStyle(
                          fontWeight: FontWeight.w800,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'These values update pricing, plan quotas, class fee rules, and account reuse policies instantly.',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                        ),
                      ),
                      const SizedBox(height: 14),
                      _settingsField(
                        'Subscription Weekly (KES)',
                        _subscriptionWeeklyKesController,
                      ),
                      _settingsField(
                        'Subscription Monthly (KES)',
                        _subscriptionMonthlyKesController,
                      ),
                      _settingsField(
                        'Subscription Annual (KES)',
                        _subscriptionAnnualKesController,
                      ),
                      _settingsField(
                        'Weekly Plan Max Exams',
                        _weeklyPlanMaxExamsController,
                      ),
                      _settingsField(
                        'Monthly Plan Max Exams',
                        _monthlyPlanMaxExamsController,
                      ),
                      _settingsField(
                        'Annual Plan Max Exams',
                        _annualPlanMaxExamsController,
                      ),
                      _settingsField(
                        'Class Escrow Platform Fee (%)',
                        _classEscrowPlatformFeePercentController,
                        keyboardType: const TextInputType.numberWithOptions(
                          decimal: true,
                        ),
                      ),
                      _settingsField(
                        'Class Min Fee (KES)',
                        _classMinFeeKesController,
                      ),
                      _settingsField(
                        'Class Max Fee (KES)',
                        _classMaxFeeKesController,
                      ),
                      _settingsField(
                        'Account Reuse Grace Days',
                        _accountReuseGraceDaysController,
                      ),
                      const SizedBox(height: 8),
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.icon(
                          onPressed: _savingSettings
                              ? null
                              : _saveRuntimeSettings,
                          icon: _savingSettings
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              : const Icon(Icons.save_rounded),
                          label: const Text('Save Runtime Settings'),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
        ],
      ),
    );
  }
}

enum _AlertLevel { ok, warning, critical }

class _SystemAlert {
  const _SystemAlert({
    required this.key,
    required this.level,
    required this.title,
    required this.detail,
    this.acknowledged = false,
    this.acknowledgedBy,
    this.acknowledgedAt,
  });

  final String key;
  final _AlertLevel level;
  final String title;
  final String detail;
  final bool acknowledged;
  final String? acknowledgedBy;
  final String? acknowledgedAt;

  _SystemAlert copyWith({
    String? key,
    _AlertLevel? level,
    String? title,
    String? detail,
    bool? acknowledged,
    String? acknowledgedBy,
    String? acknowledgedAt,
  }) {
    return _SystemAlert(
      key: key ?? this.key,
      level: level ?? this.level,
      title: title ?? this.title,
      detail: detail ?? this.detail,
      acknowledged: acknowledged ?? this.acknowledged,
      acknowledgedBy: acknowledgedBy ?? this.acknowledgedBy,
      acknowledgedAt: acknowledgedAt ?? this.acknowledgedAt,
    );
  }
}
