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
  final TextEditingController _freePlanMaxGenerationsController =
      TextEditingController();
  final TextEditingController _weeklyPlanMaxGenerationsController =
      TextEditingController();
  final TextEditingController _monthlyPlanMaxGenerationsController =
      TextEditingController();
  final TextEditingController _annualPlanMaxGenerationsController =
      TextEditingController();
  final TextEditingController _weeklyPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _monthlyPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _annualPlanMaxExamsController =
      TextEditingController();
  final TextEditingController _examPackSmallPriceKesController =
      TextEditingController();
  final TextEditingController _examPackSmallCostKesController =
      TextEditingController();
  final TextEditingController _examPackSmallExamsController =
      TextEditingController();
  final TextEditingController _examPackMediumPriceKesController =
      TextEditingController();
  final TextEditingController _examPackMediumCostKesController =
      TextEditingController();
  final TextEditingController _examPackMediumExamsController =
      TextEditingController();
  final TextEditingController _examPackLargePriceKesController =
      TextEditingController();
  final TextEditingController _examPackLargeCostKesController =
      TextEditingController();
  final TextEditingController _examPackLargeExamsController =
      TextEditingController();
  final TextEditingController _taskPackStarterPriceKesController =
      TextEditingController();
  final TextEditingController _taskPackStarterCostKesController =
      TextEditingController();
  final TextEditingController _taskPackStarterTasksController =
      TextEditingController();
  final TextEditingController _taskPackMediumPriceKesController =
      TextEditingController();
  final TextEditingController _taskPackMediumCostKesController =
      TextEditingController();
  final TextEditingController _taskPackMediumTasksController =
      TextEditingController();
  final TextEditingController _taskPackLargePriceKesController =
      TextEditingController();
  final TextEditingController _taskPackLargeCostKesController =
      TextEditingController();
  final TextEditingController _taskPackLargeTasksController =
      TextEditingController();
  final TextEditingController _topupTaskBoosterPriceKesController =
      TextEditingController();
  final TextEditingController _topupTaskBoosterCostKesController =
      TextEditingController();
  final TextEditingController _topupTaskBoosterTasksController =
      TextEditingController();
  final TextEditingController _topupExamBoosterPriceKesController =
      TextEditingController();
  final TextEditingController _topupExamBoosterCostKesController =
      TextEditingController();
  final TextEditingController _topupExamBoosterExamsController =
      TextEditingController();
  bool _examPackSmallOnOffer = false;
  bool _examPackMediumOnOffer = false;
  bool _examPackLargeOnOffer = false;
  bool _taskPackStarterOnOffer = false;
  bool _taskPackMediumOnOffer = false;
  bool _taskPackLargeOnOffer = false;
  bool _topupTaskBoosterOnOffer = false;
  bool _topupExamBoosterOnOffer = false;
  bool _legacySettingsExpanded = false;
  final TextEditingController _documentRetentionDaysController =
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
    final payments = (_integrationStatus['payments'] as Map<String, dynamic>?) ?? const {};

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

    final queuedStale = (queue['queued_stale_count'] as num?)?.toInt() ?? 0;
    final queuedAgeThreshold = (queue['queued_alert_age_minutes'] as num?)?.toInt() ?? 10;
    final oldestQueuedAge = (queue['oldest_queued_age_minutes'] as num?)?.toInt();
    if (queuedStale > 0) {
      alerts.add(
        _SystemAlert(
          key: 'generation_jobs_stuck_queued',
          level: queuedStale >= 5 ? _AlertLevel.critical : _AlertLevel.warning,
          title: 'Generation jobs stuck in queue',
          detail:
              '$queuedStale jobs older than $queuedAgeThreshold min. '
              '${oldestQueuedAge != null ? 'Oldest: $oldestQueuedAge min.' : ''}',
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
    final emailFailureRate = (brevo['email_failure_rate_24h'] as num?)?.toDouble() ?? 0;
    final emailFailureRateThreshold =
        (brevo['email_failure_rate_threshold'] as num?)?.toDouble() ?? 0.15;
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
    if (emailFailureRate >= emailFailureRateThreshold) {
      alerts.add(
        _SystemAlert(
          key: 'brevo_failure_rate_high',
          level: _AlertLevel.warning,
          title: 'Email failure rate elevated',
          detail:
              'Failure rate ${(emailFailureRate * 100).toStringAsFixed(1)}% '
              '(threshold ${(emailFailureRateThreshold * 100).toStringAsFixed(1)}%).',
        ),
      );
    }

    final pushFailureRate = (queue['push_failure_rate_24h'] as num?)?.toDouble() ?? 0;
    final pushFailureRateThreshold =
        (queue['push_failure_rate_threshold'] as num?)?.toDouble() ?? 0.2;
    if (pushFailureRate >= pushFailureRateThreshold) {
      alerts.add(
        _SystemAlert(
          key: 'push_failure_rate_high',
          level: _AlertLevel.warning,
          title: 'Push delivery failures elevated',
          detail:
              'Failure rate ${(pushFailureRate * 100).toStringAsFixed(1)}% '
              '(threshold ${(pushFailureRateThreshold * 100).toStringAsFixed(1)}%).',
        ),
      );
    }

    final callbackFailed24h = (payments['callbacks_failed_24h'] as num?)?.toInt() ?? 0;
    final callbackThreshold =
        (payments['callback_failure_alert_threshold_24h'] as num?)?.toInt() ?? 8;
    if (callbackFailed24h >= callbackThreshold) {
      alerts.add(
        _SystemAlert(
          key: 'payment_callback_failures_high',
          level: _AlertLevel.critical,
          title: 'Payment callback failures high',
          detail:
              '$callbackFailed24h failed callbacks in 24h '
              '(threshold $callbackThreshold). Check callback URL and M-Pesa logs.',
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
    _freePlanMaxGenerationsController.text = settings.freePlanMaxGenerations
        .toString();
    _weeklyPlanMaxGenerationsController.text = settings.weeklyPlanMaxGenerations
        .toString();
    _monthlyPlanMaxGenerationsController.text = settings.monthlyPlanMaxGenerations
        .toString();
    _annualPlanMaxGenerationsController.text = settings.annualPlanMaxGenerations
        .toString();
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
    _examPackSmallPriceKesController.text = settings.examPackSmallPriceKes.toString();
    _examPackSmallCostKesController.text = settings.examPackSmallCostKes.toString();
    _examPackSmallExamsController.text = settings.examPackSmallExams.toString();
    _examPackMediumPriceKesController.text = settings.examPackMediumPriceKes.toString();
    _examPackMediumCostKesController.text = settings.examPackMediumCostKes.toString();
    _examPackMediumExamsController.text = settings.examPackMediumExams.toString();
    _examPackLargePriceKesController.text = settings.examPackLargePriceKes.toString();
    _examPackLargeCostKesController.text = settings.examPackLargeCostKes.toString();
    _examPackLargeExamsController.text = settings.examPackLargeExams.toString();
    _taskPackStarterPriceKesController.text = settings.taskPackStarterPriceKes.toString();
    _taskPackStarterCostKesController.text = settings.taskPackStarterCostKes.toString();
    _taskPackStarterTasksController.text = settings.taskPackStarterTasks.toString();
    _taskPackMediumPriceKesController.text = settings.taskPackMediumPriceKes.toString();
    _taskPackMediumCostKesController.text = settings.taskPackMediumCostKes.toString();
    _taskPackMediumTasksController.text = settings.taskPackMediumTasks.toString();
    _taskPackLargePriceKesController.text = settings.taskPackLargePriceKes.toString();
    _taskPackLargeCostKesController.text = settings.taskPackLargeCostKes.toString();
    _taskPackLargeTasksController.text = settings.taskPackLargeTasks.toString();
    _topupTaskBoosterPriceKesController.text = settings.topupTaskBoosterPriceKes.toString();
    _topupTaskBoosterCostKesController.text = settings.topupTaskBoosterCostKes.toString();
    _topupTaskBoosterTasksController.text = settings.topupTaskBoosterTasks.toString();
    _topupExamBoosterPriceKesController.text = settings.topupExamBoosterPriceKes.toString();
    _topupExamBoosterCostKesController.text = settings.topupExamBoosterCostKes.toString();
    _topupExamBoosterExamsController.text = settings.topupExamBoosterExams.toString();
    _examPackSmallOnOffer = settings.examPackSmallOnOffer;
    _examPackMediumOnOffer = settings.examPackMediumOnOffer;
    _examPackLargeOnOffer = settings.examPackLargeOnOffer;
    _taskPackStarterOnOffer = settings.taskPackStarterOnOffer;
    _taskPackMediumOnOffer = settings.taskPackMediumOnOffer;
    _taskPackLargeOnOffer = settings.taskPackLargeOnOffer;
    _topupTaskBoosterOnOffer = settings.topupTaskBoosterOnOffer;
    _topupExamBoosterOnOffer = settings.topupExamBoosterOnOffer;
    _documentRetentionDaysController.text = settings.documentRetentionDays
        .toString();
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
      'free_plan_max_generations': int.tryParse(
        _freePlanMaxGenerationsController.text.trim(),
      ),
      'weekly_plan_max_generations': int.tryParse(
        _weeklyPlanMaxGenerationsController.text.trim(),
      ),
      'monthly_plan_max_generations': int.tryParse(
        _monthlyPlanMaxGenerationsController.text.trim(),
      ),
      'annual_plan_max_generations': int.tryParse(
        _annualPlanMaxGenerationsController.text.trim(),
      ),
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
      'exam_pack_small_price_kes': int.tryParse(
        _examPackSmallPriceKesController.text.trim(),
      ),
      'exam_pack_small_cost_kes': int.tryParse(
        _examPackSmallCostKesController.text.trim(),
      ),
      'exam_pack_small_exams': int.tryParse(
        _examPackSmallExamsController.text.trim(),
      ),
      'exam_pack_medium_price_kes': int.tryParse(
        _examPackMediumPriceKesController.text.trim(),
      ),
      'exam_pack_medium_cost_kes': int.tryParse(
        _examPackMediumCostKesController.text.trim(),
      ),
      'exam_pack_medium_exams': int.tryParse(
        _examPackMediumExamsController.text.trim(),
      ),
      'exam_pack_large_price_kes': int.tryParse(
        _examPackLargePriceKesController.text.trim(),
      ),
      'exam_pack_large_cost_kes': int.tryParse(
        _examPackLargeCostKesController.text.trim(),
      ),
      'exam_pack_large_exams': int.tryParse(
        _examPackLargeExamsController.text.trim(),
      ),
      'task_pack_starter_price_kes': int.tryParse(
        _taskPackStarterPriceKesController.text.trim(),
      ),
      'task_pack_starter_cost_kes': int.tryParse(
        _taskPackStarterCostKesController.text.trim(),
      ),
      'task_pack_starter_tasks': int.tryParse(
        _taskPackStarterTasksController.text.trim(),
      ),
      'task_pack_medium_price_kes': int.tryParse(
        _taskPackMediumPriceKesController.text.trim(),
      ),
      'task_pack_medium_cost_kes': int.tryParse(
        _taskPackMediumCostKesController.text.trim(),
      ),
      'task_pack_medium_tasks': int.tryParse(
        _taskPackMediumTasksController.text.trim(),
      ),
      'task_pack_large_price_kes': int.tryParse(
        _taskPackLargePriceKesController.text.trim(),
      ),
      'task_pack_large_cost_kes': int.tryParse(
        _taskPackLargeCostKesController.text.trim(),
      ),
      'task_pack_large_tasks': int.tryParse(
        _taskPackLargeTasksController.text.trim(),
      ),
      'topup_task_booster_price_kes': int.tryParse(
        _topupTaskBoosterPriceKesController.text.trim(),
      ),
      'topup_task_booster_cost_kes': int.tryParse(
        _topupTaskBoosterCostKesController.text.trim(),
      ),
      'topup_task_booster_tasks': int.tryParse(
        _topupTaskBoosterTasksController.text.trim(),
      ),
      'topup_exam_booster_price_kes': int.tryParse(
        _topupExamBoosterPriceKesController.text.trim(),
      ),
      'topup_exam_booster_cost_kes': int.tryParse(
        _topupExamBoosterCostKesController.text.trim(),
      ),
      'topup_exam_booster_exams': int.tryParse(
        _topupExamBoosterExamsController.text.trim(),
      ),
      'exam_pack_small_on_offer': _examPackSmallOnOffer,
      'exam_pack_medium_on_offer': _examPackMediumOnOffer,
      'exam_pack_large_on_offer': _examPackLargeOnOffer,
      'task_pack_starter_on_offer': _taskPackStarterOnOffer,
      'task_pack_medium_on_offer': _taskPackMediumOnOffer,
      'task_pack_large_on_offer': _taskPackLargeOnOffer,
      'topup_task_booster_on_offer': _topupTaskBoosterOnOffer,
      'topup_exam_booster_on_offer': _topupExamBoosterOnOffer,
      'document_retention_days': int.tryParse(
        _documentRetentionDaysController.text.trim(),
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

    const requiredSettingKeys = <String>{
      'free_plan_max_generations',
      'weekly_plan_max_generations',
      'monthly_plan_max_generations',
      'annual_plan_max_generations',
      'subscription_weekly_kes',
      'subscription_monthly_kes',
      'subscription_annual_kes',
      'weekly_plan_max_exams',
      'monthly_plan_max_exams',
      'annual_plan_max_exams',
      'exam_pack_small_price_kes',
      'exam_pack_small_cost_kes',
      'exam_pack_small_exams',
      'exam_pack_medium_price_kes',
      'exam_pack_medium_cost_kes',
      'exam_pack_medium_exams',
      'exam_pack_large_price_kes',
      'exam_pack_large_cost_kes',
      'exam_pack_large_exams',
      'task_pack_starter_price_kes',
      'task_pack_starter_cost_kes',
      'task_pack_starter_tasks',
      'task_pack_medium_price_kes',
      'task_pack_medium_cost_kes',
      'task_pack_medium_tasks',
      'task_pack_large_price_kes',
      'task_pack_large_cost_kes',
      'task_pack_large_tasks',
      'topup_task_booster_price_kes',
      'topup_task_booster_cost_kes',
      'topup_task_booster_tasks',
      'topup_exam_booster_price_kes',
      'topup_exam_booster_cost_kes',
      'topup_exam_booster_exams',
      'exam_pack_small_on_offer',
      'exam_pack_medium_on_offer',
      'exam_pack_large_on_offer',
      'task_pack_starter_on_offer',
      'task_pack_medium_on_offer',
      'task_pack_large_on_offer',
      'topup_task_booster_on_offer',
      'topup_exam_booster_on_offer',
      'document_retention_days',
      'class_escrow_platform_fee_percent',
      'class_min_fee_kes',
      'class_max_fee_kes',
      'account_reuse_grace_days',
    };
    final missingKeys = requiredSettingKeys
        .where((k) => !payload.containsKey(k))
        .toList();
    if (missingKeys.isNotEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Please enter valid values for all settings (${missingKeys.length} missing).',
          ),
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

  Widget _offerToggleRow(
    String label,
    bool value,
    ValueChanged<bool> onChanged,
  ) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          color: Colors.white.withValues(alpha: 0.03),
          border: Border.all(color: Colors.white10),
        ),
        child: Row(
          children: [
            Expanded(
              child: Text(
                '$label On Offer',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            Checkbox(
              value: value,
              onChanged: (v) => onChanged(v ?? false),
            ),
          ],
        ),
      ),
    );
  }

  Widget _legacyCompatibilitySection() {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        color: Colors.amber.withValues(alpha: 0.08),
        border: Border.all(color: Colors.amber.withValues(alpha: 0.24)),
      ),
      child: Column(
        children: [
          InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => setState(() => _legacySettingsExpanded = !_legacySettingsExpanded),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              child: Row(
                children: [
                  const Icon(Icons.history_rounded, size: 16, color: Colors.amberAccent),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'Legacy Compatibility (Hidden Plans)',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  Icon(
                    _legacySettingsExpanded
                        ? Icons.keyboard_arrow_up_rounded
                        : Icons.keyboard_arrow_down_rounded,
                    color: Colors.amberAccent,
                  ),
                ],
              ),
            ),
          ),
          if (_legacySettingsExpanded)
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 2, 12, 6),
              child: Column(
                children: [
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text(
                      'Used only for legacy weekly/monthly/annual subscriptions created before Credit Shop migration.',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                      ),
                    ),
                  ),
                  _settingsField(
                    'Legacy Weekly Max Generations',
                    _weeklyPlanMaxGenerationsController,
                  ),
                  _settingsField(
                    'Legacy Monthly Max Generations',
                    _monthlyPlanMaxGenerationsController,
                  ),
                  _settingsField(
                    'Legacy Annual Max Generations',
                    _annualPlanMaxGenerationsController,
                  ),
                  _settingsField(
                    'Legacy Weekly Price (KES)',
                    _subscriptionWeeklyKesController,
                  ),
                  _settingsField(
                    'Legacy Monthly Price (KES)',
                    _subscriptionMonthlyKesController,
                  ),
                  _settingsField(
                    'Legacy Annual Price (KES)',
                    _subscriptionAnnualKesController,
                  ),
                  _settingsField(
                    'Legacy Weekly Max Exams',
                    _weeklyPlanMaxExamsController,
                  ),
                  _settingsField(
                    'Legacy Monthly Max Exams',
                    _monthlyPlanMaxExamsController,
                  ),
                  _settingsField(
                    'Legacy Annual Max Exams',
                    _annualPlanMaxExamsController,
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _freePlanMaxGenerationsController.dispose();
    _weeklyPlanMaxGenerationsController.dispose();
    _monthlyPlanMaxGenerationsController.dispose();
    _annualPlanMaxGenerationsController.dispose();
    _subscriptionWeeklyKesController.dispose();
    _subscriptionMonthlyKesController.dispose();
    _subscriptionAnnualKesController.dispose();
    _weeklyPlanMaxExamsController.dispose();
    _monthlyPlanMaxExamsController.dispose();
    _annualPlanMaxExamsController.dispose();
    _examPackSmallPriceKesController.dispose();
    _examPackSmallCostKesController.dispose();
    _examPackSmallExamsController.dispose();
    _examPackMediumPriceKesController.dispose();
    _examPackMediumCostKesController.dispose();
    _examPackMediumExamsController.dispose();
    _examPackLargePriceKesController.dispose();
    _examPackLargeCostKesController.dispose();
    _examPackLargeExamsController.dispose();
    _taskPackStarterPriceKesController.dispose();
    _taskPackStarterCostKesController.dispose();
    _taskPackStarterTasksController.dispose();
    _taskPackMediumPriceKesController.dispose();
    _taskPackMediumCostKesController.dispose();
    _taskPackMediumTasksController.dispose();
    _taskPackLargePriceKesController.dispose();
    _taskPackLargeCostKesController.dispose();
    _taskPackLargeTasksController.dispose();
    _topupTaskBoosterPriceKesController.dispose();
    _topupTaskBoosterCostKesController.dispose();
    _topupTaskBoosterTasksController.dispose();
    _topupExamBoosterPriceKesController.dispose();
    _topupExamBoosterCostKesController.dispose();
    _topupExamBoosterExamsController.dispose();
    _documentRetentionDaysController.dispose();
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
                        'These values update Credit Shop pricing, retention, class fee rules, and compatibility settings instantly.',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                        ),
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'Pricing guide: Customer Price = learner charge, Internal Cost = fulfillment baseline, Included Units = exams/tasks granted.',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                        ),
                      ),
                      const SizedBox(height: 14),
                      const Text(
                        'Free Tier',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _settingsField(
                        'Free Tier Max Generations (per cycle)',
                        _freePlanMaxGenerationsController,
                      ),
                      _legacyCompatibilitySection(),
                      const SizedBox(height: 6),
                      const Text(
                        'Credit Shop: Exam Packs',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _settingsField(
                        'Small Exam Pack Customer Price (KES)',
                        _examPackSmallPriceKesController,
                      ),
                      _settingsField(
                        'Small Exam Pack Internal Cost (KES)',
                        _examPackSmallCostKesController,
                      ),
                      _settingsField(
                        'Small Exam Pack Included Exams',
                        _examPackSmallExamsController,
                      ),
                      _offerToggleRow(
                        'Small Exam Pack',
                        _examPackSmallOnOffer,
                        (v) => setState(() => _examPackSmallOnOffer = v),
                      ),
                      _settingsField(
                        'Medium Exam Pack Customer Price (KES)',
                        _examPackMediumPriceKesController,
                      ),
                      _settingsField(
                        'Medium Exam Pack Internal Cost (KES)',
                        _examPackMediumCostKesController,
                      ),
                      _settingsField(
                        'Medium Exam Pack Included Exams',
                        _examPackMediumExamsController,
                      ),
                      _offerToggleRow(
                        'Medium Exam Pack',
                        _examPackMediumOnOffer,
                        (v) => setState(() => _examPackMediumOnOffer = v),
                      ),
                      _settingsField(
                        'Large Exam Pack Customer Price (KES)',
                        _examPackLargePriceKesController,
                      ),
                      _settingsField(
                        'Large Exam Pack Internal Cost (KES)',
                        _examPackLargeCostKesController,
                      ),
                      _settingsField(
                        'Large Exam Pack Included Exams',
                        _examPackLargeExamsController,
                      ),
                      _offerToggleRow(
                        'Large Exam Pack',
                        _examPackLargeOnOffer,
                        (v) => setState(() => _examPackLargeOnOffer = v),
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'Credit Shop: Task Packs',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _settingsField(
                        'Starter Task Pack Customer Price (KES)',
                        _taskPackStarterPriceKesController,
                      ),
                      _settingsField(
                        'Starter Task Pack Internal Cost (KES)',
                        _taskPackStarterCostKesController,
                      ),
                      _settingsField(
                        'Starter Task Pack Included Tasks',
                        _taskPackStarterTasksController,
                      ),
                      _offerToggleRow(
                        'Starter Task Pack',
                        _taskPackStarterOnOffer,
                        (v) => setState(() => _taskPackStarterOnOffer = v),
                      ),
                      _settingsField(
                        'Medium Task Pack Customer Price (KES)',
                        _taskPackMediumPriceKesController,
                      ),
                      _settingsField(
                        'Medium Task Pack Internal Cost (KES)',
                        _taskPackMediumCostKesController,
                      ),
                      _settingsField(
                        'Medium Task Pack Included Tasks',
                        _taskPackMediumTasksController,
                      ),
                      _offerToggleRow(
                        'Medium Task Pack',
                        _taskPackMediumOnOffer,
                        (v) => setState(() => _taskPackMediumOnOffer = v),
                      ),
                      _settingsField(
                        'Large Task Pack Customer Price (KES)',
                        _taskPackLargePriceKesController,
                      ),
                      _settingsField(
                        'Large Task Pack Internal Cost (KES)',
                        _taskPackLargeCostKesController,
                      ),
                      _settingsField(
                        'Large Task Pack Included Tasks',
                        _taskPackLargeTasksController,
                      ),
                      _offerToggleRow(
                        'Large Task Pack',
                        _taskPackLargeOnOffer,
                        (v) => setState(() => _taskPackLargeOnOffer = v),
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'Credit Shop: Top-Ups',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _settingsField(
                        'Task Booster Customer Price (KES)',
                        _topupTaskBoosterPriceKesController,
                      ),
                      _settingsField(
                        'Task Booster Internal Cost (KES)',
                        _topupTaskBoosterCostKesController,
                      ),
                      _settingsField(
                        'Task Booster Included Tasks',
                        _topupTaskBoosterTasksController,
                      ),
                      _offerToggleRow(
                        'Task Booster',
                        _topupTaskBoosterOnOffer,
                        (v) => setState(() => _topupTaskBoosterOnOffer = v),
                      ),
                      _settingsField(
                        'Exam Booster Customer Price (KES)',
                        _topupExamBoosterPriceKesController,
                      ),
                      _settingsField(
                        'Exam Booster Internal Cost (KES)',
                        _topupExamBoosterCostKesController,
                      ),
                      _settingsField(
                        'Exam Booster Included Exams',
                        _topupExamBoosterExamsController,
                      ),
                      _offerToggleRow(
                        'Exam Booster',
                        _topupExamBoosterOnOffer,
                        (v) => setState(() => _topupExamBoosterOnOffer = v),
                      ),
                      _settingsField(
                        'Document Retention Days',
                        _documentRetentionDaysController,
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
