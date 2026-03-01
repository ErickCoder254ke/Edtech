import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:frontend/models/models.dart';
import 'package:frontend/screens/topic_suggestions_screen.dart';
import 'package:frontend/services/api_client.dart';

class _FakeApiClient extends ApiClient {
  _FakeApiClient({required this.byCategory, required this.upvoteCounts})
    : super(baseUrl: 'http://localhost');

  final Map<String, List<TopicSuggestion>> byCategory;
  final Map<String, int> upvoteCounts;
  final List<String> categoryCalls = <String>[];
  final List<String> sortCalls = <String>[];
  final List<String> upvoteCalls = <String>[];

  @override
  Future<TopicListResponse> listTopicSuggestions({
    required String accessToken,
    required String category,
    String sort = 'top',
  }) async {
    categoryCalls.add(category);
    sortCalls.add(sort);
    final source = List<TopicSuggestion>.from(byCategory[category] ?? const []);
    if (sort == 'new') {
      source.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    } else {
      source.sort((a, b) => b.upvoteCount.compareTo(a.upvoteCount));
    }
    final votes = source.fold<int>(0, (sum, item) => sum + item.upvoteCount);
    return TopicListResponse(
      items: source,
      category: category,
      categoryLabel: category,
      totalSuggestions: source.length,
      totalVotes: votes,
    );
  }

  @override
  Future<int> upvoteTopicSuggestion({
    required String accessToken,
    required String topicId,
  }) async {
    upvoteCalls.add(topicId);
    final next = (upvoteCounts[topicId] ?? 0) + 1;
    upvoteCounts[topicId] = next;
    for (final entry in byCategory.entries) {
      byCategory[entry.key] = entry.value.map((topic) {
        if (topic.id != topicId) return topic;
        return topic.copyWith(upvoteCount: next, userHasUpvoted: true);
      }).toList();
    }
    return next;
  }
}

Session _session({String role = 'student'}) {
  return Session(
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    user: User(
      id: 'u1',
      email: 'user@example.com',
      fullName: 'User One',
      role: role,
      createdAt: DateTime(2026, 2, 27),
    ),
  );
}

TopicSuggestion _topic({
  required String id,
  required String category,
  required String title,
  required int upvotes,
  bool hasVoted = false,
  String status = 'open',
  DateTime? createdAt,
}) {
  return TopicSuggestion(
    id: id,
    title: title,
    description: 'desc',
    category: category,
    categoryLabel: category,
    createdBy: 'u2',
    createdAt: createdAt ?? DateTime(2026, 2, 1),
    upvoteCount: upvotes,
    status: status,
    userHasUpvoted: hasVoted,
  );
}

Widget _wrap({required ApiClient apiClient, required Session session}) {
  return MaterialApp(
    home: TopicSuggestionsScreen(
      apiClient: apiClient,
      session: session,
      onSessionUpdated: (_) {},
      onSessionInvalid: () {},
    ),
  );
}

Future<void> _pumpUntilFound(
  WidgetTester tester,
  Finder finder, {
  int attempts = 150,
}) async {
  for (var i = 0; i < attempts; i++) {
    await tester.pump(const Duration(milliseconds: 100));
    if (finder.evaluate().isNotEmpty) {
      return;
    }
  }
}

void main() {
  testWidgets('switches category and sort and fetches accordingly', (
    tester,
  ) async {
    final api = _FakeApiClient(
      byCategory: {
        'grade_1_4': [
          _topic(id: 'a1', category: 'grade_1_4', title: 'A1', upvotes: 2),
        ],
        'junior_secondary': [
          _topic(
            id: 'b1',
            category: 'junior_secondary',
            title: 'B1',
            upvotes: 1,
          ),
        ],
      },
      upvoteCounts: {'a1': 2, 'b1': 1},
    );

    await tester.pumpWidget(_wrap(apiClient: api, session: _session()));
    await tester.pumpAndSettle();

    expect(api.categoryCalls.last, 'grade_1_4');
    expect(api.sortCalls.last, 'top');

    await tester.tap(find.byKey(const ValueKey('category-junior_secondary')));
    await tester.pumpAndSettle();
    expect(api.categoryCalls.last, 'junior_secondary');

    await tester.tap(find.byKey(const ValueKey('sort-new')));
    await tester.pumpAndSettle();
    expect(api.sortCalls.last, 'new');
  });

  testWidgets('student upvote updates state and marks voted', (tester) async {
    final topic = _topic(
      id: 't1',
      category: 'grade_1_4',
      title: 'Fractions',
      upvotes: 1,
    );
    final api = _FakeApiClient(
      byCategory: {
        'grade_1_4': [topic],
      },
      upvoteCounts: {'t1': 1},
    );

    await tester.pumpWidget(_wrap(apiClient: api, session: _session()));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.byKey(const ValueKey('upvote-t1')),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await _pumpUntilFound(tester, find.byKey(const ValueKey('upvote-t1')));

    expect(api.categoryCalls, isNotEmpty);
    expect(find.byKey(const ValueKey('upvote-t1')), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('upvote-t1')));
    await tester.pumpAndSettle();

    expect(api.upvoteCalls, ['t1']);
    expect(find.text('2'), findsOneWidget);
    expect(find.text('Voted'), findsOneWidget);
  });

  testWidgets('teacher create class preview changes status to class_created', (
    tester,
  ) async {
    final topic = _topic(
      id: 't2',
      category: 'grade_1_4',
      title: 'Integers',
      upvotes: 7,
    );
    final api = _FakeApiClient(
      byCategory: {
        'grade_1_4': [topic],
      },
      upvoteCounts: {'t2': 7},
    );

    await tester.pumpWidget(
      _wrap(
        apiClient: api,
        session: _session(role: 'teacher'),
      ),
    );
    await tester.pumpAndSettle();
    await _pumpUntilFound(
      tester,
      find.byKey(const ValueKey('teacher-create-class-t2')),
    );

    expect(find.text('Create Class (Soon)'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('teacher-create-class-t2')));
    await tester.pumpAndSettle();
    expect(find.text('Create Class (Coming Soon)'), findsOneWidget);

    await tester.tap(find.text('Preview Status'));
    await tester.pumpAndSettle();

    expect(find.text('Status: class_created'), findsOneWidget);
    expect(find.text('Class Created'), findsOneWidget);
  });
}
