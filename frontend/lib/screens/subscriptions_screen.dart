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
  String? _selectedPlanId;
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
    setState(() {
      _loading = true;
      _message = null;
    });
    try {
      final plans = await widget.apiClient.listSubscriptionPlans();
      final visiblePlans = plans.where((p) => p.visible).toList();
      final sub = await _runWithAuthRetry(
        (token) => widget.apiClient.mySubscription(accessToken: token),
      );
      if (!mounted) return;
      setState(() {
        _plans = visiblePlans;
        _currentSubscription = sub;
        _lastSyncedAt = DateTime.now();
        if (_plans.isNotEmpty) {
          final hasSelection = _selectedPlanId != null &&
              _plans.any((p) => p.planId == _selectedPlanId);
          if (!hasSelection) {
            final featured = _plans.where((p) => p.featured).toList();
            _selectedPlanId = (featured.isNotEmpty ? featured.first : _plans.first).planId;
          }
        } else {
          _selectedPlanId = null;
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
    final selected = _plans.where((p) => p.planId == _selectedPlanId).toList();
    if (selected.isEmpty) {
      setState(() => _message = 'Select a pack first.');
      return;
    }
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
          planId: selected.first.planId,
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
      setState(() => _message = 'Payment status: ${status['status'] ?? 'pending'}');
      await _load();
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _message = e.message);
    }
  }

  List<SubscriptionPlan> _byCategory(String category) {
    return _plans.where((p) => (p.category ?? '').toLowerCase() == category).toList();
  }

  String _categoryTitle(String category) {
    switch (category) {
      case 'exam_packs':
        return 'Exam Packs';
      case 'task_packs':
        return 'Task Packs';
      case 'topups':
        return 'Top-Up Packs';
      default:
        return 'Packs';
    }
  }

  IconData _categoryIcon(String category) {
    switch (category) {
      case 'exam_packs':
        return Icons.menu_book_rounded;
      case 'task_packs':
        return Icons.edit_note_rounded;
      case 'topups':
        return Icons.flash_on_rounded;
      default:
        return Icons.inventory_2_rounded;
    }
  }

  @override
  Widget build(BuildContext context) {
    final active = _currentSubscription?['active'] == true;
    final categories = const ['exam_packs', 'task_packs', 'topups'];
    SubscriptionPlan? selectedPlan;
    for (final p in _plans) {
      if (p.planId == _selectedPlanId) {
        selectedPlan = p;
        break;
      }
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Credit Shop'),
        actions: [
          IconButton(
            onPressed: _load,
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Sync latest packs',
          ),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF050A15), Color(0xFF0B1020), Color(0xFF0F1226)],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : RefreshIndicator(
                onRefresh: _load,
                child: ListView(
                  padding: const EdgeInsets.fromLTRB(16, 14, 16, 28),
                  children: [
                    GlassContainer(
                      borderRadius: 22,
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'ExamOS Credit Shop',
                            style: TextStyle(fontWeight: FontWeight.w800, fontSize: 20),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            active
                                ? 'Active pack: ${(_currentSubscription?['plan_name'] ?? _currentSubscription?['plan_id'] ?? '').toString()}'
                                : 'No active pack. Choose a pack below to continue generating.',
                            style: TextStyle(
                              color: active ? Colors.greenAccent : AppColors.textMuted,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          if ((_currentSubscription?['end_at'] ?? '').toString().isNotEmpty)
                            Padding(
                              padding: const EdgeInsets.only(top: 4),
                              child: Text(
                                'Valid until: ${_currentSubscription?['end_at']}',
                                style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                              ),
                            ),
                          if (_lastSyncedAt != null)
                            Padding(
                              padding: const EdgeInsets.only(top: 6),
                              child: Text(
                                'Rates synced: ${_lastSyncedAt!.toLocal()}',
                                style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                              ),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                    ...categories.map((category) {
                      final items = _byCategory(category);
                      if (items.isEmpty) return const SizedBox.shrink();
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 14),
                        child: _PackSection(
                          title: _categoryTitle(category),
                          icon: _categoryIcon(category),
                          plans: items,
                          selectedPlanId: _selectedPlanId,
                          onSelect: (planId) => setState(() => _selectedPlanId = planId),
                        ),
                      );
                    }),
                    GlassContainer(
                      borderRadius: 20,
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            selectedPlan == null
                                ? 'Payment'
                                : 'Payment: ${selectedPlan.name} (KES ${selectedPlan.amountKes})',
                            style: const TextStyle(fontWeight: FontWeight.w800),
                          ),
                          const SizedBox(height: 10),
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
                  ],
                ),
              ),
      ),
    );
  }
}

class _PackSection extends StatelessWidget {
  const _PackSection({
    required this.title,
    required this.icon,
    required this.plans,
    required this.selectedPlanId,
    required this.onSelect,
  });

  final String title;
  final IconData icon;
  final List<SubscriptionPlan> plans;
  final String? selectedPlanId;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: AppColors.accent),
            const SizedBox(width: 8),
            Text(title, style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 18)),
          ],
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 10,
          runSpacing: 10,
          children: plans.map((plan) {
            final selected = selectedPlanId == plan.planId;
            final width = (MediaQuery.of(context).size.width - 52) / 2;
            return GestureDetector(
              onTap: () => onSelect(plan.planId),
              child: Container(
                width: width,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  gradient: selected
                      ? LinearGradient(
                          colors: [
                            AppColors.primary.withValues(alpha: 0.28),
                            AppColors.accent.withValues(alpha: 0.16),
                          ],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        )
                      : null,
                  color: selected ? null : Colors.white.withValues(alpha: 0.05),
                  border: Border.all(
                    color: selected
                        ? AppColors.primary.withValues(alpha: 0.55)
                        : Colors.white.withValues(alpha: 0.08),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            plan.name,
                            style: const TextStyle(fontWeight: FontWeight.w800),
                          ),
                        ),
                        if (plan.onOffer)
                          _OfferBadge(
                            label: (plan.savingsLabel ?? 'On Offer').toUpperCase(),
                          )
                        else if (plan.featured)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                            decoration: BoxDecoration(
                              color: Colors.amber.withValues(alpha: 0.16),
                              borderRadius: BorderRadius.circular(999),
                            ),
                            child: const Text(
                              'HOT',
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.w800,
                                color: Colors.amberAccent,
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '${plan.unitsCount ?? plan.generationQuota} ${plan.unitsLabel ?? 'Credits'}',
                      style: const TextStyle(color: AppColors.textMuted),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      'Price: KSh ${plan.amountKes}',
                      style: const TextStyle(fontWeight: FontWeight.w700),
                    ),
                    if ((plan.description ?? '').trim().isNotEmpty)
                      Text(
                        plan.description!.trim(),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontSize: 12,
                          color: AppColors.textMuted,
                        ),
                      ),
                  ],
                ),
              ),
            );
          }).toList(),
        ),
      ],
    );
  }
}

class _OfferBadge extends StatelessWidget {
  const _OfferBadge({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(999),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFFFF5EA8).withValues(alpha: 0.45),
            blurRadius: 18,
            spreadRadius: 1.2,
          ),
          BoxShadow(
            color: const Color(0xFFFFD24A).withValues(alpha: 0.22),
            blurRadius: 14,
            spreadRadius: 0.6,
          ),
        ],
      ),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(999),
          gradient: const LinearGradient(
            colors: [Color(0xFFFF4C93), Color(0xFFFF8F45), Color(0xFFFFD24A)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          border: Border.all(
            color: Colors.white.withValues(alpha: 0.55),
            width: 0.7,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(
              Icons.local_fire_department_rounded,
              size: 12,
              color: Color(0xFF2B0D00),
            ),
            const SizedBox(width: 4),
            Text(
              label,
              style: const TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w900,
                letterSpacing: 0.4,
                color: Color(0xFF2B0D00),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
