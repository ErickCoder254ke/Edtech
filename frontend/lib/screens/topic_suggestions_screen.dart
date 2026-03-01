import 'package:flutter/material.dart';

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

  bool get _isStudent => widget.session.user.role.toLowerCase() == 'student';
  bool get _categoryAtCapacity => (_topicList?.totalSuggestions ?? 0) >= 30;

  @override
  void initState() {
    super.initState();
    _loadTopics();
  }

  @override
  void didUpdateWidget(covariant TopicSuggestionsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadTopics();
    }
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
      builder: (_) => _CreateClassFromTopicDialog(topic: item),
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
                        onUpvote: () => _upvoteTopic(topic),
                        onTeacherCreateClass: () => _teacherCreateClass(topic),
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
    required this.onUpvote,
    required this.onTeacherCreateClass,
  });

  final TopicSuggestion item;
  final bool canUpvote;
  final bool isUpvoting;
  final bool isCreatingClass;
  final VoidCallback onUpvote;
  final VoidCallback onTeacherCreateClass;

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
  const _CreateClassFromTopicDialog({required this.topic});

  final TopicSuggestion topic;

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

class _TinyChip extends StatelessWidget {
  const _TinyChip({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.06),
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
