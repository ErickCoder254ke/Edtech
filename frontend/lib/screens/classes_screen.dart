import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'teacher_verification_screen.dart';

class ClassesScreen extends StatefulWidget {
  const ClassesScreen({
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
  State<ClassesScreen> createState() => _ClassesScreenState();
}

class _ClassesScreenState extends State<ClassesScreen> {
  final _titleController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _meetingController = TextEditingController();
  final _feeController = TextEditingController(text: '0');
  DateTime? _startAt;
  DateTime? _endAt;
  bool _loading = true;
  bool _saving = false;
  String _statusFilter = 'upcoming';
  String? _error;
  List<ClassSession> _classes = [];
  int _withdrawableKes = 0;
  final Set<String> _busyClassIds = <String>{};
  int _classMinFeeKes = 50;
  int _classMaxFeeKes = 20000;

  bool get _isTeacher => widget.session.user.role.toLowerCase() == 'teacher';

  @override
  void initState() {
    super.initState();
    _loadClasses();
  }

  @override
  void didUpdateWidget(covariant ClassesScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadClasses();
    }
  }

  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
    _meetingController.dispose();
    _feeController.dispose();
    super.dispose();
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

  Future<void> _loadClasses() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final classes = await _runWithAuthRetry(
        (token) => widget.apiClient.listClassSessions(
          accessToken: token,
          status: _statusFilter,
          limit: 100,
        ),
      );
      try {
        final cfg = await widget.apiClient.getRuntimeConfig();
        _classMinFeeKes =
            (cfg['class_min_fee_kes'] as num?)?.toInt() ?? _classMinFeeKes;
        _classMaxFeeKes =
            (cfg['class_max_fee_kes'] as num?)?.toInt() ?? _classMaxFeeKes;
      } catch (_) {}
      if (!mounted) return;
      int withdrawable = _withdrawableKes;
      if (_isTeacher) {
        try {
          final earnings = await _runWithAuthRetry(
            (token) => widget.apiClient.classEarnings(accessToken: token),
          );
          withdrawable = (earnings['withdrawable_balance_kes'] as num?)?.toInt() ?? 0;
        } catch (_) {}
      }
      setState(() {
        _classes = classes;
        _withdrawableKes = withdrawable;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Failed to load classes.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _pickStartEnd() async {
    final now = DateTime.now();
    final date = await showDatePicker(
      context: context,
      firstDate: now,
      lastDate: DateTime(now.year + 2),
      initialDate: _startAt ?? now,
    );
    if (date == null) return;
    if (!mounted) return;
    final startTime = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(
        _startAt ?? now.add(const Duration(hours: 1)),
      ),
    );
    if (startTime == null) return;
    if (!mounted) return;
    final endTime = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(
        (_startAt ?? now).add(const Duration(hours: 1)),
      ),
    );
    if (endTime == null) return;
    final start = DateTime(
      date.year,
      date.month,
      date.day,
      startTime.hour,
      startTime.minute,
    );
    final end = DateTime(
      date.year,
      date.month,
      date.day,
      endTime.hour,
      endTime.minute,
    );
    setState(() {
      _startAt = start;
      _endAt = end;
    });
  }

  Future<void> _createClass() async {
    final title = _titleController.text.trim();
    final description = _descriptionController.text.trim();
    final link = _meetingController.text.trim();
    final feeKes = int.tryParse(_feeController.text.trim()) ?? -1;
    if (title.isEmpty || link.isEmpty || _startAt == null || _endAt == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Fill title, link, and schedule.')),
      );
      return;
    }
    if (feeKes < 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a valid fee amount in KES.')),
      );
      return;
    }
    if (feeKes > 0 && feeKes < _classMinFeeKes) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Fee must be at least KES $_classMinFeeKes or 0 for free class.',
          ),
        ),
      );
      return;
    }
    if (feeKes > _classMaxFeeKes) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Fee must not exceed KES $_classMaxFeeKes.')),
      );
      return;
    }
    setState(() => _saving = true);
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.createClassSession(
          accessToken: token,
          title: title,
          description: description.isEmpty ? null : description,
          meetingLink: link,
          scheduledStartAt: _startAt!,
          scheduledEndAt: _endAt!,
          feeKes: feeKes,
        ),
      );
      if (!mounted) return;
      _titleController.clear();
      _descriptionController.clear();
      _meetingController.clear();
      _feeController.text = '0';
      setState(() {
        _startAt = null;
        _endAt = null;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Class created and students alerted.')),
      );
      await _loadClasses();
    } on ApiException catch (e) {
      if (!mounted) return;
      final msg = e.message.toLowerCase();
      if (msg.contains('teacher verification')) {
        await showDialog<void>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('Verification Required'),
            content: Text(e.message),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(ctx).pop(),
                child: const Text('Close'),
              ),
              FilledButton(
                onPressed: () {
                  Navigator.of(ctx).pop();
                  Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => TeacherVerificationScreen(
                        apiClient: widget.apiClient,
                        session: widget.session,
                        onSessionUpdated: widget.onSessionUpdated,
                        onSessionInvalid: widget.onSessionInvalid,
                      ),
                    ),
                  );
                },
                child: const Text('Verify Now'),
              ),
            ],
          ),
        );
        return;
      }
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _completeClass(String classId) async {
    setState(() => _busyClassIds.add(classId));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.completeClassSession(
          accessToken: token,
          classId: classId,
        ),
      );
      if (!mounted) return;
      await _loadClasses();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _busyClassIds.remove(classId));
    }
  }

  Future<void> _joinClass(ClassSession session) async {
    setState(() => _busyClassIds.add(session.id));
    try {
      String? phone;
      if (!session.joined && session.feeKes > 0) {
        phone = await _promptPhoneForPayment();
        if (phone == null || phone.trim().isEmpty) {
          if (mounted) setState(() => _busyClassIds.remove(session.id));
          return;
        }
      }
      final result = await _runWithAuthRetry(
        (token) => widget.apiClient.joinClassSession(
          accessToken: token,
          classId: session.id,
          phoneNumber: phone,
        ),
      );
      final requiresPayment = result['requires_payment'] == true;
      if (requiresPayment) {
        final checkoutRequestId = result['checkout_request_id']?.toString() ?? '';
        final paid = await _pollPaymentUntilDone(session.id, checkoutRequestId);
        if (!paid) return;
      }
      final link = result['meeting_link']?.toString().trim().isNotEmpty == true
          ? (result['meeting_link']?.toString() ?? session.meetingLink)
          : session.meetingLink;
      final uri = Uri.tryParse(link);
      if (uri != null) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      }
      if (!mounted) return;
      await _loadClasses();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _busyClassIds.remove(session.id));
    }
  }

  Future<void> _reviewClass(ClassSession session) async {
    int rating = 5;
    final commentController = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocalState) => AlertDialog(
          title: const Text('Leave Review'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                children: [
                  const Text('Rating'),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Slider(
                      value: rating.toDouble(),
                      min: 1,
                      max: 5,
                      divisions: 4,
                      label: '$rating',
                      onChanged: (v) => setLocalState(() => rating = v.round()),
                    ),
                  ),
                ],
              ),
              TextField(
                controller: commentController,
                maxLines: 3,
                decoration: const InputDecoration(
                  hintText: 'Optional feedback',
                ),
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
      ),
    );
    if (ok != true) return;

    setState(() => _busyClassIds.add(session.id));
    try {
      await _runWithAuthRetry(
        (token) => widget.apiClient.createClassReview(
          accessToken: token,
          classId: session.id,
          rating: rating,
          comment: commentController.text.trim().isEmpty
              ? null
              : commentController.text.trim(),
        ),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Review submitted.')));
      await _loadClasses();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _busyClassIds.remove(session.id));
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

  Future<String?> _promptPhoneForPayment() async {
    final controller = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Pay Class Fee'),
        content: TextField(
          controller: controller,
          keyboardType: TextInputType.phone,
          decoration: const InputDecoration(
            hintText: 'Enter M-Pesa number (e.g. 07XXXXXXXX)',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Continue'),
          ),
        ],
      ),
    );
    if (ok != true) return null;
    return controller.text.trim();
  }

  Future<bool> _pollPaymentUntilDone(String classId, String checkoutRequestId) async {
    if (checkoutRequestId.isEmpty) {
      return false;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('STK push sent. Complete payment on your phone.')),
    );
    for (var i = 0; i < 18; i++) {
      await Future<void>.delayed(const Duration(seconds: 4));
      try {
        final status = await _runWithAuthRetry(
          (token) => widget.apiClient.classPaymentStatus(
            accessToken: token,
            classId: classId,
            checkoutRequestId: checkoutRequestId,
          ),
        );
        final paymentStatus = (status['status']?.toString() ?? '').toLowerCase();
        if (paymentStatus == 'paid') {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Payment confirmed. Joining class.')),
            );
          }
          return true;
        }
        if (paymentStatus == 'failed') {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(
                  status['result_desc']?.toString() ?? 'Payment failed or cancelled.',
                ),
              ),
            );
          }
          return false;
        }
      } catch (_) {}
    }
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Payment still pending. Check notifications and retry join.')),
      );
    }
    return false;
  }

  Future<void> _requestWithdrawal() async {
    final amountController = TextEditingController();
    final phoneController = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Withdraw Earnings'),
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
              decoration: const InputDecoration(hintText: 'M-Pesa number (optional)'),
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
    if (ok != true) return;
    final amount = int.tryParse(amountController.text.trim()) ?? 0;
    if (amount <= 0) return;
    try {
      final result = await _runWithAuthRetry(
        (token) => widget.apiClient.requestClassWithdrawal(
          accessToken: token,
          amountKes: amount,
          phoneNumber: phoneController.text.trim().isEmpty ? null : phoneController.text.trim(),
        ),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(result['message']?.toString() ?? 'Withdrawal requested.')),
      );
      await _loadClasses();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_isTeacher ? 'Class Manager' : 'Classes'),
        actions: [
          IconButton(
            onPressed: _loadClasses,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
      body: Stack(
        children: [
          const _ClassBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadClasses,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 24),
                children: [
                  if (_isTeacher) _buildCreateCard(),
                  if (_isTeacher) ...[
                    const SizedBox(height: 10),
                    _buildEarningsCard(),
                  ],
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    children: ['upcoming', 'past', 'all']
                        .map(
                          (status) => ChoiceChip(
                            label: Text(status.toUpperCase()),
                            selected: _statusFilter == status,
                            onSelected: (_) {
                              if (_statusFilter == status) return;
                              setState(() => _statusFilter = status);
                              _loadClasses();
                            },
                          ),
                        )
                        .toList(),
                  ),
                  const SizedBox(height: 10),
                  if (_loading)
                    const _LoadingTile()
                  else if (_error != null)
                    _ErrorTile(message: _error!)
                  else if (_classes.isEmpty)
                    const _EmptyTile()
                  else
                    ..._classes.map((session) => _buildClassTile(session)),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCreateCard() {
    return GlassContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Schedule New Class',
            style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _titleController,
            decoration: const InputDecoration(hintText: 'Class title'),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _descriptionController,
            maxLines: 2,
            decoration: const InputDecoration(hintText: 'Class details'),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _meetingController,
            decoration: const InputDecoration(
              hintText: 'Meeting link (Google Meet / Zoom)',
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _feeController,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              hintText: 'Class fee in KES (0 for free class)',
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Allowed fee range (admin synced): KES $_classMinFeeKes - $_classMaxFeeKes, or 0 for free class.',
            style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: Text(
                  _startAt == null || _endAt == null
                      ? 'No schedule selected'
                      : '${_fmt(_startAt!)} to ${_fmt(_endAt!)}',
                  style: const TextStyle(
                    fontSize: 12,
                    color: AppColors.textMuted,
                  ),
                ),
              ),
              TextButton.icon(
                onPressed: _pickStartEnd,
                icon: const Icon(Icons.schedule_rounded),
                label: const Text('Pick Time'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: _saving ? null : _createClass,
              icon: _saving
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.add_circle_outline_rounded),
              label: const Text('Create Class'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildClassTile(ClassSession session) {
    final busy = _busyClassIds.contains(session.id);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GlassContainer(
        borderRadius: 16,
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    session.title,
                    style: const TextStyle(
                      fontWeight: FontWeight.w800,
                      fontSize: 15,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    session.status.toUpperCase(),
                    style: const TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ],
            ),
            if ((session.description ?? '').isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(
                session.description!,
                style: const TextStyle(color: AppColors.textMuted),
              ),
            ],
            const SizedBox(height: 8),
            Text(
              'Teacher: ${session.teacherName}',
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
            Text(
              'Schedule: ${_fmt(session.scheduledStartAt)} - ${_fmt(session.scheduledEndAt)}',
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
            Text(
              'Fee: KES ${session.feeKes}  Duration: ${session.durationMinutes} min',
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                _MiniMeta(text: 'Joins ${session.joinCount}'),
                const SizedBox(width: 8),
                _MiniMeta(
                  text: session.averageRating == null
                      ? 'No rating'
                      : 'Rating ${session.averageRating} (${session.reviewCount})',
                ),
              ],
            ),
            const SizedBox(height: 10),
            if (_isTeacher) ...[
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: busy || session.status == 'completed'
                          ? null
                          : () => _completeClass(session.id),
                      icon: busy
                          ? const SizedBox(
                              width: 14,
                              height: 14,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.check_circle_outline_rounded),
                      label: const Text('Mark Completed'),
                    ),
                  ),
                ],
              ),
            ] else ...[
              Row(
                children: [
                  Expanded(
                    child: FilledButton.icon(
                      onPressed: busy ? null : () => _joinClass(session),
                      icon: busy
                          ? const SizedBox(
                              width: 14,
                              height: 14,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.video_call_rounded),
                      label: Text(
                        session.joined
                            ? 'Join Again'
                            : session.feeKes > 0
                            ? 'Pay & Join'
                            : 'Join Class',
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: busy ? null : () => _reviewClass(session),
                      icon: const Icon(Icons.rate_review_outlined),
                      label: const Text('Review'),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildEarningsCard() {
    return GlassContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Escrow Earnings',
                  style: TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
                ),
                const SizedBox(height: 4),
                Text(
                  'Withdrawable: KES $_withdrawableKes',
                  style: const TextStyle(color: AppColors.textMuted),
                ),
              ],
            ),
          ),
          FilledButton.icon(
            onPressed: _withdrawableKes > 0 ? _requestWithdrawal : null,
            icon: const Icon(Icons.account_balance_wallet_outlined),
            label: const Text('Withdraw'),
          ),
        ],
      ),
    );
  }
}

class _MiniMeta extends StatelessWidget {
  const _MiniMeta({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: Colors.white12),
      ),
      child: Text(
        text,
        style: const TextStyle(fontSize: 11, color: AppColors.textMuted),
      ),
    );
  }
}

class _ClassBackground extends StatelessWidget {
  const _ClassBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF0A1020), Color(0xFF050913)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
    );
  }
}

class _LoadingTile extends StatelessWidget {
  const _LoadingTile();

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
          Text('Loading classes...'),
        ],
      ),
    );
  }
}

class _ErrorTile extends StatelessWidget {
  const _ErrorTile({required this.message});

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

class _EmptyTile extends StatelessWidget {
  const _EmptyTile();

  @override
  Widget build(BuildContext context) {
    return const GlassContainer(
      borderRadius: 16,
      padding: EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('No classes yet', style: TextStyle(fontWeight: FontWeight.w700)),
          SizedBox(height: 4),
          Text(
            'Scheduled classes will appear here.',
            style: TextStyle(color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }
}
