import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import 'teacher_verification_screen.dart';

class TopicSuggestionsScreen extends StatefulWidget {
  const TopicSuggestionsScreen({
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
  State<TopicSuggestionsScreen> createState() => _TopicSuggestionsScreenState();
}

class _TopicSuggestionsScreenState extends State<TopicSuggestionsScreen> {
  static const List<Map<String, String>> _categories = [
    {'key': 'grade_1_4', 'label': 'Grade 1-4'},
    {'key': 'grade_5_6', 'label': 'Grade 5-6'},
    {'key': 'junior_secondary', 'label': 'Junior Secondary'},
    {'key': 'senior_secondary', 'label': 'Senior Secondary'},
  ];

  final TextEditingController _titleController = TextEditingController();
  final TextEditingController _descriptionController = TextEditingController();
  bool _loading = true;
  bool _submitting = false;
  String? _error;
  String _category = _categories.first['key']!;
  String _sort = 'top';
  TopicListResponse? _topicList;
  final Set<String> _upvotingIds = <String>{};
  final Set<String> _creatingClassIds = <String>{};
  final Set<String> _joiningClassIds = <String>{};
  final Set<String> _paidClassIds = <String>{};
  final Set<String> _completedClassIds = <String>{};
  final Map<String, ClassSession> _linkedClasses = <String, ClassSession>{};
  final Map<String, DateTime> _linkedClassFetchedAt = <String, DateTime>{};
  int _classMinFeeKes = 50;
  int _classMaxFeeKes = 20000;

  bool get _isStudent => widget.session.user.role.toLowerCase() == 'student';
  bool get _categoryAtCapacity => (_topicList?.totalSuggestions ?? 0) >= 30;

  @override
  void initState() {
    super.initState();
    _loadRuntimeConfig();
    _loadTopics();
  }

  @override
  void didUpdateWidget(covariant TopicSuggestionsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadRuntimeConfig();
      _loadTopics();
    }
  }

  Future<void> _loadRuntimeConfig() async {
    try {
      final cfg = await widget.apiClient.getRuntimeConfig();
      if (!mounted) return;
      setState(() {
        _classMinFeeKes =
            (cfg['class_min_fee_kes'] as num?)?.toInt() ?? _classMinFeeKes;
        _classMaxFeeKes =
            (cfg['class_max_fee_kes'] as num?)?.toInt() ?? _classMaxFeeKes;
      });
    } catch (_) {}
  }

  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
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

  Future<void> _loadTopics() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final result = await _runWithAuthRetry(
        (token) => widget.apiClient.listTopicSuggestions(
          accessToken: token,
          category: _category,
          sort: _sort,
        ),
      );
      if (!mounted) return;
      setState(() => _topicList = result);
      _loadLinkedClassesForTopics(result.items);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load topic suggestions right now.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadLinkedClassesForTopics(List<TopicSuggestion> topics) async {
    final classIds = topics
        .map((t) => t.linkedClassId?.trim() ?? '')
        .where((id) => id.isNotEmpty)
        .toSet();
    if (classIds.isEmpty) {
      if (mounted) {
        setState(() => _linkedClasses.clear());
      }
      return;
    }
    final now = DateTime.now();
    final staleBefore = now.subtract(const Duration(seconds: 45));
    final fetchIds = classIds
        .where(
          (id) =>
              !_linkedClasses.containsKey(id) ||
              (_linkedClassFetchedAt[id]?.isBefore(staleBefore) ?? true),
        )
        .take(12)
        .toList();
    if (fetchIds.isEmpty) return;
    final Map<String, ClassSession> next = <String, ClassSession>{};
    await Future.wait(
      fetchIds.map((classId) async {
        try {
          final session = await _runWithAuthRetry(
            (token) => widget.apiClient.getClassSession(
              accessToken: token,
              classId: classId,
            ),
          );
          next[classId] = session;
        } catch (_) {}
      }),
    );
    if (!mounted) return;
    setState(() {
      _linkedClasses.addAll(next);
      for (final entry in next.entries) {
        _linkedClassFetchedAt[entry.key] = now;
        final paymentStatus = (entry.value.paymentStatus ?? '').toLowerCase();
        if (paymentStatus == 'paid' || paymentStatus == 'free') {
          _paidClassIds.add(entry.key);
        }
        if (entry.value.status.toLowerCase() == 'completed') {
          _completedClassIds.add(entry.key);
        }
      }
    });
  }

  String? _buildClassMetaLabel(String classId) {
    final session = _linkedClasses[classId];
    if (session == null) return null;
    final now = DateTime.now();
    final start = session.scheduledStartAt.toLocal();
    final end = session.scheduledEndAt.toLocal();
    final status = session.status.toLowerCase();
    if (status == 'completed') return 'Completed';
    if (status == 'cancelled') return 'Cancelled';
    if (now.isAfter(start) && now.isBefore(end)) {
      final minutes = end.difference(now).inMinutes;
      if (minutes > 0) return 'Ongoing - ends in $minutes min';
      return 'Ongoing';
    }
    if (now.isBefore(start)) {
      final minutes = start.difference(now).inMinutes;
      if (minutes < 60) return 'Starts in ${minutes.clamp(1, 59)} min';
      final hours = start.difference(now).inHours;
      if (hours < 24) return 'Starts in $hours hr';
      return 'Starts ${start.year}-${start.month.toString().padLeft(2, '0')}-${start.day.toString().padLeft(2, '0')}';
    }
    return 'Ended';
  }

  String? _buildClassFeeLabel(String classId) {
    final session = _linkedClasses[classId];
    if (session == null) return null;
    if (session.feeKes <= 0) return 'Free class';
    return 'KES ${session.feeKes}';
  }

  _ChipTone _classMetaTone(String? classMetaLabel) {
    final text = (classMetaLabel ?? '').toLowerCase();
    if (text.startsWith('ongoing')) return _ChipTone.success;
    if (text.startsWith('starts in')) return _ChipTone.warning;
    if (text.contains('completed') || text.contains('cancelled') || text == 'ended') {
      return _ChipTone.neutral;
    }
    return _ChipTone.neutral;
  }

  Future<void> _submitTopic() async {
    final title = _titleController.text.trim();
    final description = _descriptionController.text.trim();
    if (title.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Topic title is required.')));
      return;
    }
    setState(() => _submitting = true);
    try {
      final topic = await _runWithAuthRetry(
        (token) => widget.apiClient.createTopicSuggestion(
          accessToken: token,
          title: title,
          description: description.isEmpty ? null : description,
          category: _category,
        ),
      );
      if (!mounted) return;
      _titleController.clear();
      _descriptionController.clear();
      setState(() {
        final existing = _topicList;
        final items = <TopicSuggestion>[topic];
        if (existing != null) {
          items.addAll(existing.items);
          _topicList = TopicListResponse(
            items: items,
            category: existing.category,
            categoryLabel: existing.categoryLabel,
            totalSuggestions: existing.totalSuggestions + 1,
            totalVotes: existing.totalVotes,
          );
        }
      });
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Topic suggestion posted.')));
      await _loadTopics();
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.message.toLowerCase().contains('teacher verification')) {
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
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _upvoteTopic(TopicSuggestion item) async {
    if (item.userHasUpvoted || _upvotingIds.contains(item.id)) return;
    setState(() => _upvotingIds.add(item.id));
    try {
      final newCount = await _runWithAuthRetry(
        (token) => widget.apiClient.upvoteTopicSuggestion(
          accessToken: token,
          topicId: item.id,
        ),
      );
      if (!mounted) return;
      final list = _topicList;
      if (list != null) {
        final updatedItems = list.items.map((topic) {
          if (topic.id != item.id) return topic;
          return topic.copyWith(upvoteCount: newCount, userHasUpvoted: true);
        }).toList();
        setState(() {
          _topicList = TopicListResponse(
            items: updatedItems,
            category: list.category,
            categoryLabel: list.categoryLabel,
            totalSuggestions: list.totalSuggestions,
            totalVotes: list.totalVotes + 1,
          );
        });
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _upvotingIds.remove(item.id));
    }
  }

  Future<void> _teacherCreateClass(TopicSuggestion item) async {
    final draft = await showDialog<_TopicClassDraft>(
      context: context,
      builder: (_) => _CreateClassFromTopicDialog(
        topic: item,
        classMinFeeKes: _classMinFeeKes,
        classMaxFeeKes: _classMaxFeeKes,
      ),
    );
    if (draft == null) return;
    setState(() => _creatingClassIds.add(item.id));
    try {
      final createdClass = await _runWithAuthRetry(
        (token) => widget.apiClient.createClassFromTopic(
          accessToken: token,
          topicId: item.id,
          title: draft.title,
          description: draft.description,
          meetingLink: draft.meetingLink,
          scheduledStartAt: draft.startAt,
          scheduledEndAt: draft.endAt,
          feeKes: draft.feeKes,
        ),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Class created from topic demand. Class ID: ${createdClass.id}',
          ),
        ),
      );
      await _loadTopics();
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _creatingClassIds.remove(item.id));
    }
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
    if (checkoutRequestId.isEmpty) return false;
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
              const SnackBar(content: Text('Payment confirmed. You can now join the class.')),
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
        const SnackBar(content: Text('Payment still pending. Retry join in a few seconds.')),
      );
    }
    return false;
  }

  Future<void> _studentJoinClassFromTopic(TopicSuggestion item) async {
    if (!_isStudent) return;
    final classId = item.linkedClassId?.trim() ?? '';
    if (classId.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Class link is not available yet for this topic.')),
      );
      return;
    }
    if (_joiningClassIds.contains(classId)) return;
    setState(() => _joiningClassIds.add(classId));
    try {
      final classSession = await _runWithAuthRetry(
        (token) => widget.apiClient.getClassSession(
          accessToken: token,
          classId: classId,
        ),
      );
      if (mounted) {
        setState(() {
          _linkedClasses[classId] = classSession;
          _linkedClassFetchedAt[classId] = DateTime.now();
        });
      }
      final classPaymentStatus = (classSession.paymentStatus ?? '').toLowerCase();
      final hasPaidAlready = classPaymentStatus == 'paid' || classPaymentStatus == 'free';
      if (hasPaidAlready && mounted) {
        setState(() => _paidClassIds.add(classId));
      }
      if (classSession.status.toLowerCase() == 'completed') {
        if (mounted) {
          setState(() => _completedClassIds.add(classId));
        }
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('This class is already completed.')),
        );
        return;
      }

      final needsPhoneForPaidFlow =
          !classSession.joined &&
          (classSession.paymentRequired || classSession.feeKes > 0) &&
          !hasPaidAlready &&
          !_paidClassIds.contains(classId);
      String? phone;
      if (needsPhoneForPaidFlow) {
        phone = await _promptPhoneForPayment();
        if (phone == null || phone.trim().isEmpty) return;
      }

      var result = await _runWithAuthRetry(
        (token) => widget.apiClient.joinClassSession(
          accessToken: token,
          classId: classId,
          phoneNumber: phone,
        ),
      );

      if (result['requires_payment'] == true) {
        final checkoutRequestId = result['checkout_request_id']?.toString() ?? '';
        final paid = await _pollPaymentUntilDone(classId, checkoutRequestId);
        if (!paid) return;
        if (mounted) {
          setState(() => _paidClassIds.add(classId));
        }
        result = await _runWithAuthRetry(
          (token) => widget.apiClient.joinClassSession(
            accessToken: token,
            classId: classId,
          ),
        );
      }

      final paymentStatus = (result['payment_status']?.toString() ?? '').toLowerCase();
      if (paymentStatus == 'paid' || paymentStatus == 'free') {
        if (mounted) {
          setState(() => _paidClassIds.add(classId));
        }
      }

      final link = result['meeting_link']?.toString().trim().isNotEmpty == true
          ? (result['meeting_link']?.toString() ?? classSession.meetingLink)
          : classSession.meetingLink;
      if (link.trim().isEmpty) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Join link is not available right now.')),
        );
        return;
      }
      final uri = Uri.tryParse(link);
      if (uri != null) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      }
      await _loadTopics();
    } on ApiException catch (e) {
      final message = e.message.toLowerCase();
      if (message.contains('already completed')) {
        if (mounted) {
          setState(() => _completedClassIds.add(classId));
        }
      }
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _joiningClassIds.remove(classId));
    }
  }

  Future<void> _openSubmitSheet() async {
    if (!_isStudent) return;
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        final bottomInset = MediaQuery.of(ctx).viewInsets.bottom;
        return Padding(
          padding: EdgeInsets.fromLTRB(12, 12, 12, bottomInset + 12),
          child: GlassContainer(
            borderRadius: 18,
            padding: const EdgeInsets.all(14),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Suggest a Topic',
                  style: TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 10),
                TextField(
                  key: const ValueKey('topic-title-input'),
                  controller: _titleController,
                  maxLength: 180,
                  decoration: const InputDecoration(
                    labelText: 'Title',
                    hintText: 'e.g. Fractions and mixed numbers',
                  ),
                ),
                const SizedBox(height: 6),
                TextField(
                  key: const ValueKey('topic-description-input'),
                  controller: _descriptionController,
                  maxLength: 400,
                  minLines: 2,
                  maxLines: 4,
                  decoration: const InputDecoration(
                    labelText: 'Description (optional)',
                  ),
                ),
                if (_categoryAtCapacity)
                  const Padding(
                    padding: EdgeInsets.only(top: 2, bottom: 8),
                    child: Text(
                      'Category is full. Upvote existing suggestions.',
                      style: TextStyle(color: Colors.amberAccent, fontSize: 12),
                    ),
                  ),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    key: const ValueKey('post-topic-button'),
                    onPressed: (_submitting || _categoryAtCapacity)
                        ? null
                        : () async {
                            await _submitTopic();
                            if (ctx.mounted && !_submitting) {
                              Navigator.of(ctx).pop();
                            }
                          },
                    icon: const Icon(Icons.send_rounded),
                    label: Text(_submitting ? 'Posting...' : 'Post Suggestion'),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final suggestions = _topicList?.items ?? const <TopicSuggestion>[];
    final demandVotes = _topicList?.totalVotes ?? 0;
    final demandTopics = _topicList?.totalSuggestions ?? 0;

    return Scaffold(
      body: Stack(
        children: [
          const _TopicsBackground(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _loadTopics,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 120),
                children: [
                  _DemandHeader(
                    totalVotes: demandVotes,
                    totalTopics: demandTopics,
                    categoryLimit: 30,
                    currentCategoryLabel:
                        _topicList?.categoryLabel ??
                        _categories.firstWhere(
                          (c) => c['key'] == _category,
                        )['label']!,
                  ),
                  const SizedBox(height: 8),
                  _CategoryStrip(
                    categories: _categories,
                    selected: _category,
                    onSelect: (next) {
                      if (_category == next) return;
                      setState(() => _category = next);
                      _loadTopics();
                    },
                  ),
                  const SizedBox(height: 8),
                  _SortStrip(
                    selectedSort: _sort,
                    onSelect: (value) {
                      if (_sort == value) return;
                      setState(() => _sort = value);
                      _loadTopics();
                    },
                  ),
                  const SizedBox(height: 8),
                  if (_isStudent)
                    _StudentActionBar(
                      categoryAtCapacity: _categoryAtCapacity,
                      onSuggestTopic: _openSubmitSheet,
                    )
                  else
                    const _TeacherHintCard(),
                  const SizedBox(height: 10),
                  if (_loading) const _LoadingCard(),
                  if (_error != null) _ErrorCard(message: _error!),
                  if (!_loading && _error == null && suggestions.isEmpty)
                    const _EmptyStateCard()
                  else if (!_loading && _error == null)
                    ...suggestions.map(
                      (topic) => _TopicCard(
                        item: topic,
                        canUpvote: _isStudent,
                        isUpvoting: _upvotingIds.contains(topic.id),
                        isCreatingClass: _creatingClassIds.contains(topic.id),
                        isJoiningClass: _joiningClassIds.contains(topic.linkedClassId ?? ''),
                        hasPaidClassAccess: _paidClassIds.contains(topic.linkedClassId ?? ''),
                        isClassCompleted: _completedClassIds.contains(topic.linkedClassId ?? ''),
                        classMetaLabel: topic.linkedClassId == null
                            ? null
                            : _buildClassMetaLabel(topic.linkedClassId!.trim()),
                        classFeeLabel: topic.linkedClassId == null
                            ? null
                            : _buildClassFeeLabel(topic.linkedClassId!.trim()),
                        classMetaTone: topic.linkedClassId == null
                            ? _ChipTone.neutral
                            : _classMetaTone(_buildClassMetaLabel(topic.linkedClassId!.trim())),
                        onUpvote: () => _upvoteTopic(topic),
                        onTeacherCreateClass: () => _teacherCreateClass(topic),
                        onStudentJoinClass: () => _studentJoinClassFromTopic(topic),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DemandHeader extends StatelessWidget {
  const _DemandHeader({
    required this.totalVotes,
    required this.totalTopics,
    required this.categoryLimit,
    required this.currentCategoryLabel,
  });

  final int totalVotes;
  final int totalTopics;
  final int categoryLimit;
  final String currentCategoryLabel;

  @override
  Widget build(BuildContext context) {
    final usedPct = categoryLimit > 0
        ? (totalTopics / categoryLimit).clamp(0, 1).toDouble()
        : 0.0;
    return GlassContainer(
      borderRadius: 16,
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
      child: Column(
        children: [
          Row(
            children: [
              const Icon(Icons.forum_rounded, size: 18, color: AppColors.accent),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  currentCategoryLabel,
                  style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13),
                ),
              ),
              _MetricPill(icon: Icons.how_to_vote_rounded, label: 'Votes', value: '$totalVotes'),
              const SizedBox(width: 6),
              _MetricPill(
                icon: Icons.topic_rounded,
                label: 'Topics',
                value: '$totalTopics/$categoryLimit',
              ),
            ],
          ),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(999),
            child: LinearProgressIndicator(
              value: usedPct,
              minHeight: 5,
              backgroundColor: Colors.white10,
              valueColor: AlwaysStoppedAnimation<Color>(
                usedPct >= 1 ? Colors.redAccent : AppColors.accent,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricPill extends StatelessWidget {
  const _MetricPill({
    required this.icon,
    required this.label,
    required this.value,
  });

  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Colors.white12),
      ),
      child: Row(
        children: [
          Icon(icon, size: 17, color: AppColors.accent),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: const TextStyle(
                    fontSize: 10,
                    color: AppColors.textMuted,
                  ),
                ),
                Text(
                  value,
                  style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 12),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _CategoryStrip extends StatelessWidget {
  const _CategoryStrip({
    required this.categories,
    required this.selected,
    required this.onSelect,
  });

  final List<Map<String, String>> categories;
  final String selected;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 36,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        itemBuilder: (_, index) {
          final item = categories[index];
          final key = item['key']!;
          final isActive = key == selected;
          return GestureDetector(
            key: ValueKey('category-$key'),
            onTap: () => onSelect(key),
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
                  item['label']!,
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
        itemCount: categories.length,
      ),
    );
  }
}

class _SortStrip extends StatelessWidget {
  const _SortStrip({required this.selectedSort, required this.onSelect});

  final String selectedSort;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        const Text('Sort', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
        const SizedBox(width: 6),
        ChoiceChip(
          key: const ValueKey('sort-top'),
          label: const Text('Top', style: TextStyle(fontSize: 12)),
          visualDensity: VisualDensity.compact,
          selected: selectedSort == 'top',
          onSelected: (_) => onSelect('top'),
        ),
        const SizedBox(width: 6),
        ChoiceChip(
          key: const ValueKey('sort-new'),
          label: const Text('New', style: TextStyle(fontSize: 12)),
          visualDensity: VisualDensity.compact,
          selected: selectedSort == 'new',
          onSelected: (_) => onSelect('new'),
        ),
      ],
    );
  }
}

class _StudentActionBar extends StatelessWidget {
  const _StudentActionBar({
    required this.categoryAtCapacity,
    required this.onSuggestTopic,
  });

  final bool categoryAtCapacity;
  final VoidCallback onSuggestTopic;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Text(
            categoryAtCapacity
                ? 'Category full. Upvote to signal demand.'
                : 'Got an idea? Add a topic.',
            style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
          ),
        ),
        const SizedBox(width: 8),
        FilledButton.icon(
          onPressed: categoryAtCapacity ? null : onSuggestTopic,
          icon: const Icon(Icons.add_rounded, size: 18),
          label: const Text('Suggest'),
        ),
      ],
    );
  }
}

class _TeacherHintCard extends StatelessWidget {
  const _TeacherHintCard();

  @override
  Widget build(BuildContext context) {
    return const GlassContainer(
      borderRadius: 18,
      padding: EdgeInsets.all(14),
      child: Row(
        children: [
          Icon(Icons.school_rounded, color: AppColors.accent),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'Teacher mode: monitor demand and upvotes by category.',
              style: TextStyle(color: AppColors.textMuted),
            ),
          ),
        ],
      ),
    );
  }
}

class _TopicCard extends StatelessWidget {
  const _TopicCard({
    required this.item,
    required this.canUpvote,
    required this.isUpvoting,
    required this.isCreatingClass,
    required this.isJoiningClass,
    required this.hasPaidClassAccess,
    required this.isClassCompleted,
    required this.classMetaLabel,
    required this.classFeeLabel,
    required this.classMetaTone,
    required this.onUpvote,
    required this.onTeacherCreateClass,
    required this.onStudentJoinClass,
  });

  final TopicSuggestion item;
  final bool canUpvote;
  final bool isUpvoting;
  final bool isCreatingClass;
  final bool isJoiningClass;
  final bool hasPaidClassAccess;
  final bool isClassCompleted;
  final String? classMetaLabel;
  final String? classFeeLabel;
  final _ChipTone classMetaTone;
  final VoidCallback onUpvote;
  final VoidCallback onTeacherCreateClass;
  final VoidCallback onStudentJoinClass;

  String _dateLabel(DateTime dt) {
    final local = dt.toLocal();
    final y = local.year.toString().padLeft(4, '0');
    final m = local.month.toString().padLeft(2, '0');
    final d = local.day.toString().padLeft(2, '0');
    return '$y-$m-$d';
  }

  @override
  Widget build(BuildContext context) {
    final alreadyVoted = item.userHasUpvoted;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GlassContainer(
        borderRadius: 16,
        padding: const EdgeInsets.all(13),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Column(
              children: [
                IconButton(
                  key: ValueKey('upvote-${item.id}'),
                  onPressed: (!canUpvote || alreadyVoted || isUpvoting)
                      ? null
                      : onUpvote,
                  icon: isUpvoting
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Icon(
                          alreadyVoted
                              ? Icons.arrow_circle_up_rounded
                              : Icons.arrow_circle_up_outlined,
                          color: alreadyVoted
                              ? AppColors.accent
                              : Colors.white70,
                        ),
                ),
                Text(
                  '${item.upvoteCount}',
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
              ],
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    item.title,
                    style: const TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 15,
                    ),
                  ),
                  if ((item.description ?? '').trim().isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(
                      item.description!,
                      style: const TextStyle(color: AppColors.textMuted),
                    ),
                  ],
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 8,
                    runSpacing: 6,
                    children: [
                      _TinyChip(text: 'Status: ${item.status}'),
                      if ((classMetaLabel ?? '').isNotEmpty)
                        _TinyChip(text: classMetaLabel!, tone: classMetaTone),
                      if ((classFeeLabel ?? '').isNotEmpty)
                        _TinyChip(text: classFeeLabel!, tone: _ChipTone.info),
                      _TinyChip(text: _dateLabel(item.createdAt)),
                      if (alreadyVoted) const _TinyChip(text: 'Voted'),
                    ],
                  ),
                  if (!canUpvote) ...[
                    const SizedBox(height: 10),
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        key: ValueKey('teacher-create-class-${item.id}'),
                        onPressed: (item.status == 'open' && !isCreatingClass)
                            ? onTeacherCreateClass
                            : null,
                        icon: isCreatingClass
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : const Icon(Icons.class_rounded, size: 18),
                        label: Text(
                          item.status == 'class_created'
                              ? 'Class Created'
                              : (isCreatingClass
                                    ? 'Creating Class...'
                                    : 'Create Class'),
                        ),
                      ),
                    ),
                  ],
                  if (canUpvote &&
                      item.status == 'class_created' &&
                      (item.linkedClassId?.trim().isNotEmpty == true)) ...[
                    const SizedBox(height: 10),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton.icon(
                        key: ValueKey('student-join-class-${item.id}'),
                        onPressed: (isJoiningClass || isClassCompleted)
                            ? null
                            : onStudentJoinClass,
                        icon: isJoiningClass
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : Icon(
                                isClassCompleted
                                    ? Icons.event_busy_rounded
                                    : (hasPaidClassAccess
                                          ? Icons.login_rounded
                                          : Icons.lock_open_rounded),
                                size: 18,
                              ),
                        label: Text(
                          isClassCompleted
                              ? 'Class Completed'
                              : (isJoiningClass
                                    ? 'Processing...'
                                    : (hasPaidClassAccess ? 'Join' : 'Pay & Join')),
                        ),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TopicClassDraft {
  _TopicClassDraft({
    required this.title,
    required this.description,
    required this.meetingLink,
    required this.startAt,
    required this.endAt,
    required this.feeKes,
  });

  final String title;
  final String? description;
  final String meetingLink;
  final DateTime startAt;
  final DateTime endAt;
  final int feeKes;
}

class _CreateClassFromTopicDialog extends StatefulWidget {
  const _CreateClassFromTopicDialog({
    required this.topic,
    required this.classMinFeeKes,
    required this.classMaxFeeKes,
  });

  final TopicSuggestion topic;
  final int classMinFeeKes;
  final int classMaxFeeKes;

  @override
  State<_CreateClassFromTopicDialog> createState() =>
      _CreateClassFromTopicDialogState();
}

class _CreateClassFromTopicDialogState extends State<_CreateClassFromTopicDialog> {
  late final TextEditingController _titleController;
  late final TextEditingController _descriptionController;
  final TextEditingController _meetingLinkController = TextEditingController();
  final TextEditingController _feeController = TextEditingController(text: '0');
  DateTime? _startAt;
  DateTime? _endAt;

  @override
  void initState() {
    super.initState();
    _titleController = TextEditingController(text: widget.topic.title);
    _descriptionController = TextEditingController(
      text: (widget.topic.description ?? '').trim(),
    );
  }

  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
    _meetingLinkController.dispose();
    _feeController.dispose();
    super.dispose();
  }

  Future<void> _pickSchedule() async {
    final now = DateTime.now();
    final date = await showDatePicker(
      context: context,
      firstDate: now,
      lastDate: DateTime(now.year + 2),
      initialDate: _startAt ?? now,
    );
    if (date == null || !mounted) return;
    final startTime = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(
        _startAt ?? now.add(const Duration(hours: 1)),
      ),
    );
    if (startTime == null || !mounted) return;
    final endTime = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(
        (_startAt ?? now).add(const Duration(hours: 2)),
      ),
    );
    if (endTime == null) return;
    setState(() {
      _startAt = DateTime(
        date.year,
        date.month,
        date.day,
        startTime.hour,
        startTime.minute,
      );
      _endAt = DateTime(
        date.year,
        date.month,
        date.day,
        endTime.hour,
        endTime.minute,
      );
    });
  }

  String _scheduleLabel() {
    if (_startAt == null || _endAt == null) return 'Select date & time';
    return '${_startAt!.toLocal()}  ->  ${_endAt!.toLocal()}';
  }

  void _submit() {
    final title = _titleController.text.trim();
    final meetingLink = _meetingLinkController.text.trim();
    final description = _descriptionController.text.trim();
    final feeKes = int.tryParse(_feeController.text.trim()) ?? -1;
    if (title.isEmpty || meetingLink.isEmpty || _startAt == null || _endAt == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Title, meeting link, and schedule are required.')),
      );
      return;
    }
    if (feeKes < 0) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Fee must be 0 or more.')));
      return;
    }
    if (feeKes > 0 && feeKes < widget.classMinFeeKes) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Fee must be at least KES ${widget.classMinFeeKes} or 0 for free class.',
          ),
        ),
      );
      return;
    }
    if (feeKes > widget.classMaxFeeKes) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Fee must not exceed KES ${widget.classMaxFeeKes}.'),
        ),
      );
      return;
    }
    Navigator.of(context).pop(
      _TopicClassDraft(
        title: title,
        description: description.isEmpty ? null : description,
        meetingLink: meetingLink,
        startAt: _startAt!,
        endAt: _endAt!,
        feeKes: feeKes,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create Class From Topic'),
      content: SizedBox(
        width: 520,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              TextField(
                controller: _titleController,
                textInputAction: TextInputAction.next,
                decoration: const InputDecoration(
                  labelText: 'Class title',
                  hintText: 'Topic title or a class-ready variant',
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _descriptionController,
                minLines: 2,
                maxLines: 4,
                decoration: const InputDecoration(
                  labelText: 'Description (optional)',
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _meetingLinkController,
                keyboardType: TextInputType.url,
                decoration: const InputDecoration(
                  labelText: 'Meeting link',
                  hintText: 'https://meet.google.com/...',
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _feeController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Fee (KES)',
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Allowed (admin synced): KES ${widget.classMinFeeKes}-${widget.classMaxFeeKes}, or 0 for free class.',
                style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
              ),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: _pickSchedule,
                icon: const Icon(Icons.schedule_rounded),
                label: Text(_scheduleLabel()),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _submit,
          child: const Text('Create Class'),
        ),
      ],
    );
  }
}

enum _ChipTone { neutral, success, warning, info }

class _TinyChip extends StatelessWidget {
  const _TinyChip({required this.text, this.tone = _ChipTone.neutral});

  final String text;
  final _ChipTone tone;

  Color _bgColor() {
    switch (tone) {
      case _ChipTone.success:
        return Colors.green.withValues(alpha: 0.16);
      case _ChipTone.warning:
        return Colors.orange.withValues(alpha: 0.16);
      case _ChipTone.info:
        return AppColors.primary.withValues(alpha: 0.16);
      case _ChipTone.neutral:
        return Colors.white.withValues(alpha: 0.06);
    }
  }

  Color _borderColor() {
    switch (tone) {
      case _ChipTone.success:
        return Colors.green.withValues(alpha: 0.4);
      case _ChipTone.warning:
        return Colors.orange.withValues(alpha: 0.4);
      case _ChipTone.info:
        return AppColors.primary.withValues(alpha: 0.5);
      case _ChipTone.neutral:
        return Colors.white12;
    }
  }

  Color _textColor() {
    switch (tone) {
      case _ChipTone.success:
        return Colors.greenAccent.shade100;
      case _ChipTone.warning:
        return Colors.orangeAccent.shade100;
      case _ChipTone.info:
        return AppColors.primary;
      case _ChipTone.neutral:
        return AppColors.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: _bgColor(),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: _borderColor()),
      ),
      child: Text(
        text,
        style: TextStyle(fontSize: 11, color: _textColor()),
      ),
    );
  }
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard();

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
          Text('Loading suggestions...'),
        ],
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  const _ErrorCard({required this.message});

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

class _EmptyStateCard extends StatelessWidget {
  const _EmptyStateCard();

  @override
  Widget build(BuildContext context) {
    return const GlassContainer(
      borderRadius: 16,
      padding: EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'No suggestions yet',
            style: TextStyle(fontWeight: FontWeight.w700),
          ),
          SizedBox(height: 4),
          Text(
            'Be the first to suggest what should be taught in this category.',
            style: TextStyle(color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }
}

class _TopicsBackground extends StatelessWidget {
  const _TopicsBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF09111E), Color(0xFF111827)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            top: -60,
            right: -60,
            child: _GlowOrb(color: AppColors.primary.withValues(alpha: 0.12)),
          ),
          Positioned(
            bottom: -70,
            left: -70,
            child: _GlowOrb(color: AppColors.accent.withValues(alpha: 0.08)),
          ),
        ],
      ),
    );
  }
}

class _GlowOrb extends StatelessWidget {
  const _GlowOrb({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 220,
      height: 220,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
        boxShadow: [BoxShadow(color: color, blurRadius: 120, spreadRadius: 10)],
      ),
    );
  }
}
