import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

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
      ]);
      final summary = results[0] as AdminDashboardSummary;
      final runtimeSettings = results[1] as AdminRuntimeSettings;
      if (!mounted) return;
      setState(() {
        _summary = summary;
        _runtimeSettings = runtimeSettings;
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
