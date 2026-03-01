import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';

class SubscriptionsScreen extends StatefulWidget {
  const SubscriptionsScreen({
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
  State<SubscriptionsScreen> createState() => _SubscriptionsScreenState();
}

class _SubscriptionsScreenState extends State<SubscriptionsScreen> {
  final TextEditingController _phoneController = TextEditingController();
  List<SubscriptionPlan> _plans = [];
  String _selectedPlanId = 'monthly';
  bool _loading = true;
  bool _processing = false;
  Map<String, dynamic>? _currentSubscription;
  String? _checkoutRequestId;
  String? _message;
  DateTime? _lastSyncedAt;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _phoneController.dispose();
    super.dispose();
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String accessToken) op) async {
    try {
      return await op(widget.session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      final refreshed = await widget.apiClient.refreshTokens(
        refreshToken: widget.session.refreshToken,
      );
      final nextSession = refreshed.toSession();
      widget.onSessionUpdated(nextSession);
      return await op(nextSession.accessToken);
    }
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final plans = await widget.apiClient.listSubscriptionPlans();
      final sub = await _runWithAuthRetry(
        (token) => widget.apiClient.mySubscription(accessToken: token),
      );
      if (!mounted) return;
      setState(() {
        _plans = plans;
        _currentSubscription = sub;
        _lastSyncedAt = DateTime.now();
        if (_plans.isNotEmpty && !_plans.any((p) => p.planId == _selectedPlanId)) {
          _selectedPlanId = _plans.first.planId;
        }
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _message = e.message);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _payNow() async {
    final phone = _phoneController.text.trim();
    if (phone.isEmpty) {
      setState(() => _message = 'Enter M-Pesa phone number');
      return;
    }
    setState(() {
      _processing = true;
      _message = null;
    });
    try {
      final result = await _runWithAuthRetry(
        (token) => widget.apiClient.startSubscriptionCheckout(
          accessToken: token,
          planId: _selectedPlanId,
          phoneNumber: phone,
        ),
      );
      if (!mounted) return;
      setState(() {
        _checkoutRequestId = result['checkout_request_id']?.toString();
        _message = result['customer_message']?.toString() ??
            'STK push sent. Complete payment on your phone.';
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _message = e.message);
    } finally {
      if (mounted) setState(() => _processing = false);
    }
  }

  Future<void> _refreshPaymentStatus() async {
    final checkout = _checkoutRequestId;
    if (checkout == null || checkout.isEmpty) return;
    try {
      final status = await _runWithAuthRetry(
        (token) => widget.apiClient.subscriptionPaymentStatus(
          accessToken: token,
          checkoutRequestId: checkout,
        ),
      );
      if (!mounted) return;
      setState(() {
        _message = 'Payment status: ${status['status'] ?? 'pending'}';
      });
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _message = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final active = _currentSubscription?['active'] == true;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Subscriptions'),
        actions: [
          IconButton(
            onPressed: _load,
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Sync latest rates',
          ),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : RefreshIndicator(
                onRefresh: _load,
                child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
                children: [
                  GlassContainer(
                    borderRadius: 20,
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          active
                              ? 'Active Plan: ${(_currentSubscription?['plan_name'] ?? _currentSubscription?['plan_id'] ?? '').toString()}'
                              : 'No active subscription',
                          style: TextStyle(
                            fontWeight: FontWeight.w700,
                            color: active ? Colors.greenAccent : Colors.orangeAccent,
                          ),
                        ),
                        if ((_currentSubscription?['end_at'] ?? '').toString().isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(top: 6),
                            child: Text(
                              'Valid until: ${_currentSubscription?['end_at']}',
                              style: const TextStyle(color: AppColors.textMuted),
                            ),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (_lastSyncedAt != null)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Text(
                        'Rates synced: ${_lastSyncedAt!.toLocal()}',
                        style: const TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ..._plans.map((plan) {
                    final selected = plan.planId == _selectedPlanId;
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: GestureDetector(
                        onTap: () => setState(() => _selectedPlanId = plan.planId),
                        child: GlassContainer(
                          borderRadius: 18,
                          padding: const EdgeInsets.all(14),
                          child: Row(
                            children: [
                              Icon(
                                selected ? Icons.radio_button_checked : Icons.radio_button_off,
                                color: selected ? AppColors.primary : AppColors.textMuted,
                              ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      '${plan.name} - KES ${plan.amountKes}',
                                      style: const TextStyle(fontWeight: FontWeight.w700),
                                    ),
                                    Text(
                                      '${plan.cycleDays} days • ${plan.generationQuota} generations'
                                      '${plan.examQuota != null ? ' • ${plan.examQuota} exams' : ''}'
                                      '${plan.discountPct > 0 ? ' • ${plan.discountPct}% off' : ''}'
                                      '${plan.savingsLabel != null ? ' • ${plan.savingsLabel}' : ''}',
                                      style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    );
                  }),
                  const SizedBox(height: 4),
                  TextField(
                    controller: _phoneController,
                    keyboardType: TextInputType.phone,
                    decoration: const InputDecoration(
                      labelText: 'M-Pesa Phone (e.g. 07XXXXXXXX)',
                    ),
                  ),
                  const SizedBox(height: 10),
                  GradientButton(
                    label: 'Pay with M-Pesa',
                    icon: Icons.phone_android_rounded,
                    onPressed: _processing ? null : _payNow,
                    isLoading: _processing,
                  ),
                  if (_checkoutRequestId != null) ...[
                    const SizedBox(height: 10),
                    OutlinedButton.icon(
                      onPressed: _refreshPaymentStatus,
                      icon: const Icon(Icons.refresh_rounded),
                      label: const Text('Refresh Payment Status'),
                    ),
                  ],
                  if ((_message ?? '').isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(_message!, style: const TextStyle(color: AppColors.textMuted)),
                  ],
                ],
              ),
              ),
      ),
    );
  }
}
