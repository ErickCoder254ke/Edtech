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
  static const List<Map<String, String>> _gradeFilters = [
    {'key': 'all', 'label': 'All'},
    {'key': 'grade_1_4', 'label': 'Grade 1-4'},
    {'key': 'grade_5_6', 'label': 'Grade 5-6'},
    {'key': 'junior_secondary', 'label': 'Junior Secondary'},
    {'key': 'senior_secondary', 'label': 'Senior Secondary'},
  ];
  final _titleController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _meetingController = TextEditingController();
  final _feeController = TextEditingController(text: '0');
  DateTime? _startAt;
  DateTime? _endAt;
  bool _loading = true;
  bool _saving = false;
  String _statusFilter = 'upcoming';
  String _gradeFilter = 'all';
  String? _error;
  List<ClassSession> _classes = [];
  int _withdrawableKes = 0;
  final Set<String> _busyClassIds = <String>{};
  final Set<String> _paymentPendingClassIds = <String>{};
  final Map<String, int> _tabCounts = <String, int>{};
  int _classMinFeeKes = 50;
  int _classMaxFeeKes = 20000;
  double _classPlatformFeePercent = 10;

  bool get _isTeacher => widget.session.user.role.toLowerCase() == 'teacher';
  List<String> get _statusTabs => _isTeacher
      ? const ['upcoming', 'past', 'reviews']
      : const ['upcoming', 'to_review', 'past'];

  String _backendStatusForFilter() {
    if (_isTeacher) {
      return _statusFilter == 'reviews' ? 'all' : _statusFilter;
    }
    if (_statusFilter == 'to_review') return 'past';
    return _statusFilter;
  }

  bool _isClassEnded(ClassSession session) {
    if (session.status.toLowerCase() == 'completed') return true;
    return !session.scheduledEndAt.isAfter(DateTime.now());
  }

  String _inferGradeBucket(ClassSession session) {
    final level = (session.classLevel ?? '').trim().toLowerCase();
    if (level.isNotEmpty && level != 'all') {
      return level;
    }
    final text = '${session.title} ${session.description ?? ''}'.toLowerCase();
    final gradeMatch = RegExp(r'\bgrade\s*([0-9]{1,2})\b').firstMatch(text);
    if (gradeMatch != null) {
      final grade = int.tryParse(gradeMatch.group(1) ?? '');
      if (grade != null) {
        if (grade >= 1 && grade <= 4) return 'grade_1_4';
        if (grade >= 5 && grade <= 6) return 'grade_5_6';
        if (grade >= 7 && grade <= 9) return 'junior_secondary';
        if (grade >= 10 && grade <= 12) return 'senior_secondary';
      }
    }
    final formMatch = RegExp(r'\bform\s*([1-4])\b').firstMatch(text);
    if (formMatch != null) {
      return 'senior_secondary';
    }
    if (text.contains('junior secondary')) return 'junior_secondary';
    if (text.contains('senior secondary')) return 'senior_secondary';
    if (text.contains('upper primary')) return 'grade_5_6';
    if (text.contains('lower primary')) return 'grade_1_4';
    return 'all';
  }

  List<ClassSession> _applyLocalFilter(List<ClassSession> input) {
    bool gradePass(ClassSession c) {
      if (_gradeFilter == 'all') return true;
      return _inferGradeBucket(c) == _gradeFilter;
    }
    if (_isTeacher) {
      if (_statusFilter == 'reviews') {
        return input.where((c) => c.reviewCount > 0 && gradePass(c)).toList();
      }
      return input.where(gradePass).toList();
    }

    if (_statusFilter == 'to_review') {
      return input
          .where((c) => _isClassEnded(c) && c.joined && !c.studentReviewed && gradePass(c))
          .toList();
    }

    if (_statusFilter == 'past') {
      return input
          .where(
            (c) =>
                _isClassEnded(c) &&
                (!c.joined || c.studentReviewed) &&
                gradePass(c),
          )
          .toList();
    }

    return input.where(gradePass).toList();
  }

  int _countForTab(String status, List<ClassSession> allClasses) {
    if (_isTeacher) {
      if (status == 'reviews') {
        return allClasses.where((c) => c.reviewCount > 0).length;
      }
      if (status == 'upcoming') {
        return allClasses.where((c) => !_isClassEnded(c)).length;
      }
      if (status == 'past') {
        return allClasses.where((c) => _isClassEnded(c)).length;
      }
      return allClasses.length;
    }

    if (status == 'upcoming') {
      return allClasses.where((c) => !_isClassEnded(c)).length;
    }
    if (status == 'to_review') {
      return allClasses.where((c) => _isClassEnded(c) && c.joined && !c.studentReviewed).length;
    }
    if (status == 'past') {
      return allClasses
          .where((c) => _isClassEnded(c) && (!c.joined || c.studentReviewed))
          .length;
    }
    return allClasses.length;
  }

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
          status: _backendStatusForFilter(),
          limit: 100,
        ),
      );
      final allClasses = await _runWithAuthRetry(
        (token) => widget.apiClient.listClassSessions(
          accessToken: token,
          status: 'all',
          limit: 200,
        ),
      );
      try {
        final cfg = await widget.apiClient.getRuntimeConfig();
        _classMinFeeKes =
            (cfg['class_min_fee_kes'] as num?)?.toInt() ?? _classMinFeeKes;
        _classMaxFeeKes =
            (cfg['class_max_fee_kes'] as num?)?.toInt() ?? _classMaxFeeKes;
        _classPlatformFeePercent =
            (cfg['class_escrow_platform_fee_percent'] as num?)?.toDouble() ??
                _classPlatformFeePercent;
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
        _classes = _applyLocalFilter(classes);
        for (final tab in _statusTabs) {
          _tabCounts[tab] = _countForTab(tab, allClasses);
        }
        _withdrawableKes = withdrawable;
        _paymentPendingClassIds.removeWhere((id) {
          ClassSession? matched;
          for (final c in _classes) {
            if (c.id == id) {
              matched = c;
              break;
            }
          }
          if (matched == null) return true;
          final status = (matched.paymentStatus ?? '').toLowerCase();
          return status == 'paid' || status == 'free' || matched.joined;
        });
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

  Future<void> _openClassMeeting(String link) async {
    final uri = Uri.tryParse(link);
    if (uri == null) return;
    await launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  Future<void> _joinClass(ClassSession session) async {
    setState(() => _busyClassIds.add(session.id));
    try {
      Future<Map<String, dynamic>> joinWithRetry({String? phoneNumber}) async {
        ApiException? lastError;
        for (var attempt = 1; attempt <= 3; attempt++) {
          try {
            return await _runWithAuthRetry(
              (token) => widget.apiClient.joinClassSession(
                accessToken: token,
                classId: session.id,
                phoneNumber: phoneNumber,
              ),
            );
          } on ApiException catch (e) {
            lastError = e;
            final detail = e.message.toLowerCase();
            final retryableInitConflict =
                e.statusCode == 409 &&
                detail.contains('payment is already being initiated') &&
                attempt < 3;
            if (!retryableInitConflict) {
              rethrow;
            }
            await Future.delayed(const Duration(seconds: 2));
          }
        }
        throw lastError ?? ApiException('Unable to join class.');
      }

      var result = await joinWithRetry();
      final checkoutFromFirst = (result['checkout_request_id']?.toString() ?? '').trim();
      if (result['requires_payment'] == true && checkoutFromFirst.isEmpty) {
        final savedNumbersRaw = (result['saved_phone_numbers'] as List<dynamic>? ?? const []);
        final savedNumbers = savedNumbersRaw.map((e) => e.toString()).where((e) => e.trim().isNotEmpty).toList();
        final phone = await _promptPhoneForPayment(savedNumbers: savedNumbers);
        if (phone == null || phone.trim().isEmpty) {
          if (mounted) {
            final msg = result['message']?.toString().trim();
            if ((msg ?? '').isNotEmpty) {
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg!)));
            }
          }
          return;
        }
        result = await joinWithRetry(phoneNumber: phone);
      }
      final paymentStatus = (result['payment_status']?.toString() ?? '').toLowerCase();
      if (paymentStatus == 'pending' || result['requires_payment'] == true) {
        if (mounted) setState(() => _paymentPendingClassIds.add(session.id));
      }
      if (result['requires_payment'] == true) {
        final checkoutRequestId = result['checkout_request_id']?.toString() ?? '';
        final paid = await _pollPaymentUntilDone(session.id, checkoutRequestId);
        if (!paid) return;
        if (mounted) setState(() => _paymentPendingClassIds.remove(session.id));
        result = await joinWithRetry();
      }
      final link = result['meeting_link']?.toString().trim().isNotEmpty == true
          ? (result['meeting_link']?.toString() ?? session.meetingLink)
          : session.meetingLink;
      if (link.trim().isEmpty) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Complete payment first to unlock class meeting link.'),
            ),
          );
        }
        return;
      }
      await _openClassMeeting(link);
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

  Future<void> _viewClassReviews(ClassSession session) async {
    setState(() => _busyClassIds.add(session.id));
    try {
      final reviews = await _runWithAuthRetry(
        (token) => widget.apiClient.listClassReviews(
          accessToken: token,
          classId: session.id,
        ),
      );
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text('Reviews - ${session.title}'),
          content: SizedBox(
            width: 420,
            child: reviews.isEmpty
                ? const Text('No reviews yet.')
                : ListView.separated(
                    shrinkWrap: true,
                    itemCount: reviews.length,
                    separatorBuilder: (_, __) => const Divider(height: 16),
                    itemBuilder: (_, i) {
                      final r = reviews[i];
                      final who = (r.studentName ?? '').trim().isNotEmpty
                          ? r.studentName!.trim()
                          : 'Student ${r.studentId.substring(0, r.studentId.length >= 6 ? 6 : r.studentId.length)}';
                      final stars = '★' * r.rating + '☆' * (5 - r.rating);
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('$stars  $who', style: const TextStyle(fontWeight: FontWeight.w700)),
                          if ((r.comment ?? '').trim().isNotEmpty) ...[
                            const SizedBox(height: 4),
                            Text(r.comment!.trim(), style: const TextStyle(color: AppColors.textMuted)),
                          ],
                          const SizedBox(height: 4),
                          Text(_fmt(r.createdAt), style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
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

  Future<String?> _promptPhoneForPayment({List<String> savedNumbers = const []}) async {
    final customController = TextEditingController();
    String selected = savedNumbers.isNotEmpty ? savedNumbers.first : '';
    bool useCustom = savedNumbers.isEmpty;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocalState) => AlertDialog(
          title: const Text('Pay Class Fee'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (savedNumbers.isNotEmpty) ...[
                const Text(
                  'Use a saved M-Pesa number or enter another number (e.g. parent).',
                  style: TextStyle(fontSize: 12, color: AppColors.textMuted),
                ),
                const SizedBox(height: 8),
                DropdownButtonFormField<String>(
                  value: selected,
                  items: savedNumbers
                      .map((n) => DropdownMenuItem<String>(value: n, child: Text(n)))
                      .toList(),
                  onChanged: (v) {
                    if (v == null) return;
                    setLocalState(() {
                      selected = v;
                      useCustom = false;
                    });
                  },
                  decoration: const InputDecoration(labelText: 'Saved number'),
                ),
                const SizedBox(height: 8),
                SwitchListTile.adaptive(
                  contentPadding: EdgeInsets.zero,
                  value: useCustom,
                  onChanged: (v) => setLocalState(() => useCustom = v),
                  title: const Text('Use another number'),
                ),
                const SizedBox(height: 6),
              ],
              if (useCustom)
                TextField(
                  controller: customController,
                  keyboardType: TextInputType.phone,
                  decoration: const InputDecoration(
                    hintText: 'Enter M-Pesa number (e.g. 07XXXXXXXX)',
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
              child: const Text('Continue'),
            ),
          ],
        ),
      ),
    );
    if (ok != true) return null;
    if (useCustom) return customController.text.trim();
    return selected.trim();
  }

  Future<bool> _pollPaymentUntilDone(String classId, String checkoutRequestId) async {
    if (checkoutRequestId.isEmpty) {
      return false;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('STK push sent. Complete payment on your phone.')),
    );
    for (var i = 0; i < 30; i++) {
      if (i > 0) {
        final waitSeconds = i < 10 ? 2 : 3;
        await Future<void>.delayed(Duration(seconds: waitSeconds));
      }
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
            setState(() => _paymentPendingClassIds.remove(classId));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Payment confirmed. Joining class.')),
            );
          }
          return true;
        }
        if (paymentStatus == 'failed') {
          if (mounted) {
            setState(() => _paymentPendingClassIds.remove(classId));
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
                    children: _statusTabs
                        .map(
                          (status) => ChoiceChip(
                            label: Text(
                              '${status == 'to_review' ? 'TO BE REVIEWED' : status.toUpperCase()} (${_tabCounts[status] ?? 0})',
                            ),
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
                  const SizedBox(height: 8),
                  SizedBox(
                    height: 36,
                    child: ListView.separated(
                      scrollDirection: Axis.horizontal,
                      itemBuilder: (_, index) {
                        final filter = _gradeFilters[index];
                        final key = filter['key']!;
                        final label = filter['label']!;
                        final isActive = _gradeFilter == key;
                        return GestureDetector(
                          onTap: () {
                            if (_gradeFilter == key) return;
                            setState(() => _gradeFilter = key);
                            _loadClasses();
                          },
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                            decoration: BoxDecoration(
                              color: isActive
                                  ? AppColors.primary.withValues(alpha: 0.22)
                                  : Colors.white10,
                              borderRadius: BorderRadius.circular(999),
                              border: Border.all(
                                color: isActive
                                    ? AppColors.primary.withValues(alpha: 0.55)
                                    : Colors.white12,
                              ),
                            ),
                            child: Center(
                              child: Text(
                                label,
                                style: TextStyle(
                                  fontWeight: FontWeight.w700,
                                  fontSize: 11,
                                  color: isActive ? AppColors.primary : Colors.white,
                                ),
                              ),
                            ),
                          ),
                        );
                      },
                      separatorBuilder: (_, __) => const SizedBox(width: 8),
                      itemCount: _gradeFilters.length,
                    ),
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
    final localPending = _paymentPendingClassIds.contains(session.id);
    final paymentStatusLower = (session.paymentStatus ?? '').toLowerCase();
    final hasPaidAccess =
        session.joined || paymentStatusLower == 'paid' || paymentStatusLower == 'free';
    final showPending = localPending || paymentStatusLower == 'pending';
    final ctaLabel = hasPaidAccess
        ? 'Join Class'
        : showPending
        ? 'Awaiting Payment'
        : (session.paymentRequired || session.feeKes > 0)
        ? 'Pay & Join'
        : 'Join Class';
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
            if (session.feeKes > 0)
              Text(
                'Escrow: You pay KES ${session.feeKes}. Teacher receives KES ${session.teacherNetKes} after class completion. Platform fee ${(session.platformFeePercent > 0 ? session.platformFeePercent : _classPlatformFeePercent).toStringAsFixed(1)}%',
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
                const SizedBox(width: 8),
                if (!_isTeacher)
                  _MiniMeta(
                    text: showPending
                        ? 'payment pending'
                        : session.paymentRequired
                        ? 'payment required'
                        : (session.paymentStatus ?? (session.feeKes > 0 ? 'unpaid' : 'free')),
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
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: busy
                          ? null
                          : () async {
                              if (_statusFilter != 'reviews') {
                                setState(() => _statusFilter = 'reviews');
                                await _loadClasses();
                              }
                              if (!mounted) return;
                              await _viewClassReviews(session);
                            },
                      icon: const Icon(Icons.reviews_outlined),
                      label: const Text('View Reviews'),
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
                        ctaLabel,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: busy ||
                              !session.joined ||
                              session.studentReviewed ||
                              (session.status != 'completed' &&
                                  session.scheduledEndAt.isAfter(DateTime.now()))
                          ? null
                          : () => _reviewClass(session),
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
