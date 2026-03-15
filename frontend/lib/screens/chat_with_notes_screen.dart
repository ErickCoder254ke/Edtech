import 'dart:async';

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class ChatWithNotesScreen extends StatefulWidget {
  const ChatWithNotesScreen({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onSessionUpdated,
    required this.onSessionInvalid,
    required this.documentIds,
    required this.cbcNoteIds,
  });

  final ApiClient apiClient;
  final Session session;
  final ValueChanged<Session> onSessionUpdated;
  final VoidCallback onSessionInvalid;
  final List<String> documentIds;
  final List<String> cbcNoteIds;

  @override
  State<ChatWithNotesScreen> createState() => _ChatWithNotesScreenState();
}

class _ChatWithNotesScreenState extends State<ChatWithNotesScreen> {
  final List<_ChatTurn> _turns = <_ChatTurn>[];
  final TextEditingController _controller = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  bool _sending = false;
  late Session _session;

  final Map<String, String> _docTitles = <String, String>{};

  @override
  void initState() {
    super.initState();
    _session = widget.session;
    _primeDocTitles();
  }

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String token) op) async {
    try {
      return await op(_session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      try {
        final refreshed = await widget.apiClient.refreshTokens(
          refreshToken: _session.refreshToken,
        );
        final next = refreshed.toSession();
        widget.onSessionUpdated(next);
        if (mounted) setState(() => _session = next);
        return await op(next.accessToken);
      } on ApiException {
        widget.onSessionInvalid();
        rethrow;
      }
    }
  }

  Future<void> _primeDocTitles() async {
    if (widget.documentIds.isEmpty) return;
    try {
      final docs = await _runWithAuthRetry((token) => widget.apiClient.listDocuments(token));
      final wanted = widget.documentIds.toSet();
      final nextMap = <String, String>{};
      for (final doc in docs) {
        if (wanted.contains(doc.id)) {
          nextMap[doc.id] = doc.filename;
        }
      }
      if (!mounted) return;
      setState(() {
        _docTitles
          ..clear()
          ..addAll(nextMap);
      });
    } catch (_) {
      // Non-fatal; sources will show ids.
    }
  }

  Future<void> _send() async {
    if (_sending) return;
    final message = _controller.text.trim();
    if (message.isEmpty) return;

    _controller.clear();
    setState(() {
      _turns.add(_ChatTurn.user(message));
      _sending = true;
    });
    _scrollToBottom();

    try {
      final history = _turns
          .take(20)
          .map((t) => ChatMessage(role: t.role, content: t.content))
          .toList(growable: false);

      final response = await _runWithAuthRetry(
        (token) => widget.apiClient.chatWithNotes(
          accessToken: token,
          documentIds: widget.documentIds,
          cbcNoteIds: widget.cbcNoteIds,
          message: message,
          history: history,
        ),
      );

      if (!mounted) return;
      setState(() {
        _turns.add(
          _ChatTurn.assistant(
            response.answer,
            sources: response.sources,
          ),
        );
      });
      _scrollToBottom();
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _turns.add(_ChatTurn.assistant('Error: ${e.message}'));
      });
      _scrollToBottom();
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _turns.add(_ChatTurn.assistant('Error: Unable to chat right now.'));
      });
      _scrollToBottom();
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _scrollToBottom() {
    scheduleMicrotask(() {
      if (!_scrollController.hasClients) return;
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent + 220,
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOut,
      );
    });
  }

  String _sourceTitle(ChatSource source) {
    final docId = source.documentId.trim();
    if (docId.startsWith('note:')) {
      final id = docId.substring(5);
      return 'Shared note $id';
    }
    return _docTitles[docId] ?? 'Document $docId';
  }

  String _sourceSubtitle(ChatSource source) {
    final score = source.score;
    final scoreText = score == null ? '' : ' • score ${score.toStringAsFixed(2)}';
    return 'Chunk ${source.chunkIndex}$scoreText';
  }

  void _showSourcesSheet(List<ChatSource> sources) {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) => SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
          child: GlassContainer(
            borderRadius: 22,
            padding: const EdgeInsets.all(14),
            child: ConstrainedBox(
              constraints: BoxConstraints(
                maxHeight: MediaQuery.of(ctx).size.height * 0.65,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.source_rounded, color: AppColors.accent),
                      const SizedBox(width: 8),
                      Text(
                        'Sources (${sources.length})',
                        style: const TextStyle(
                          fontWeight: FontWeight.w800,
                          fontSize: 14,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        onPressed: () => Navigator.pop(ctx),
                        icon: const Icon(Icons.close_rounded),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'These are the note/document chunks used to answer your question.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: ListView.separated(
                      itemCount: sources.length,
                      separatorBuilder: (_, __) => const Divider(height: 14),
                      itemBuilder: (context, index) {
                        final s = sources[index];
                        return ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.description_outlined, color: Colors.white70),
                          title: Text(
                            _sourceTitle(s),
                            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                          ),
                          subtitle: Text(
                            _sourceSubtitle(s),
                            style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                          ),
                        );
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _introCard() {
    final docCount = widget.documentIds.length;
    final noteCount = widget.cbcNoteIds.length;
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Ask anything from your selected notes',
            style: TextStyle(fontWeight: FontWeight.w800, fontSize: 14),
          ),
          const SizedBox(height: 6),
          Text(
            'Using $docCount document(s) and $noteCount shared note(s).',
            style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _quickChip('Explain osmosis like an exam answer'),
              _quickChip('Break down photosynthesis steps'),
              _quickChip('Give 3 examples and answers'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _quickChip(String text) {
    return ActionChip(
      label: Text(
        text,
        style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700),
      ),
      onPressed: () {
        _controller.text = text;
        _controller.selection = TextSelection.fromPosition(
          TextPosition(offset: _controller.text.length),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Chat with Notes'),
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: Column(
          children: [
            Expanded(
              child: ListView.builder(
                controller: _scrollController,
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                itemCount: _turns.isEmpty ? 1 : _turns.length,
                itemBuilder: (context, index) {
                  if (_turns.isEmpty) {
                    return _introCard();
                  }
                  final turn = _turns[index];
                  final isUser = turn.role == 'user';
                  final bubbleColor = isUser
                      ? AppColors.primary.withValues(alpha: 0.18)
                      : Colors.white.withValues(alpha: 0.06);

                  return Align(
                    alignment:
                        isUser ? Alignment.centerRight : Alignment.centerLeft,
                    child: ConstrainedBox(
                      constraints: BoxConstraints(
                        maxWidth: MediaQuery.of(context).size.width * 0.90,
                      ),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(vertical: 6),
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            color: bubbleColor,
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(
                              color: Colors.white.withValues(alpha: 0.08),
                            ),
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  turn.content,
                                  style: TextStyle(
                                    color: isUser ? Colors.white : Colors.white70,
                                    fontSize: 13,
                                    height: 1.35,
                                  ),
                                ),
                                if (!isUser && turn.sources.isNotEmpty) ...[
                                  const SizedBox(height: 10),
                                  Wrap(
                                    spacing: 8,
                                    runSpacing: 6,
                                    children: turn.sources
                                        .map(
                                          (s) => GestureDetector(
                                            onTap: () => _showSourcesSheet(turn.sources),
                                            child: Chip(
                                              avatar: const Icon(
                                                Icons.source_outlined,
                                                size: 14,
                                                color: AppColors.accent,
                                              ),
                                              label: Text(
                                                _sourceTitle(s),
                                                style: const TextStyle(fontSize: 11),
                                              ),
                                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                              backgroundColor: Colors.white.withValues(alpha: 0.05),
                                              shape: RoundedRectangleBorder(
                                                side: BorderSide(color: AppColors.glassBorder),
                                                borderRadius: BorderRadius.circular(12),
                                              ),
                                            ),
                                          ),
                                        )
                                        .toList(),
                                  ),
                                ],
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
            if (_sending)
              const Padding(
                padding: EdgeInsets.symmetric(horizontal: 16),
                child: LinearProgressIndicator(minHeight: 2.5),
              ),
            SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 16),
                child: Row(
                  children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
              child: GlassContainer(
                borderRadius: 14,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                child: Row(
                  children: [
                    const Icon(Icons.shield_outlined, size: 18, color: AppColors.accent),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Answers come only from your selected notes. If it is not in the notes, the assistant will say so.',
                        style: const TextStyle(fontSize: 12, color: Colors.white70, height: 1.3),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            Expanded(
                      child: TextField(
                        controller: _controller,
                        minLines: 1,
                        maxLines: 4,
                        textInputAction: TextInputAction.send,
                        onSubmitted: (_) => _send(),
                        decoration: const InputDecoration(
                          hintText: 'Ask about a concept from the selected notes...',
                        ),
                      ),
                    ),
                    const SizedBox(width: 10),
                    FilledButton.icon(
                      onPressed: _sending ? null : _send,
                      icon: const Icon(Icons.send_rounded, size: 18),
                      label: const Text('Send'),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ChatTurn {
  _ChatTurn({required this.role, required this.content, this.sources = const []});

  final String role;
  final String content;
  final List<ChatSource> sources;

  factory _ChatTurn.user(String content) => _ChatTurn(role: 'user', content: content);

  factory _ChatTurn.assistant(String content, {List<ChatSource> sources = const []}) =>
      _ChatTurn(role: 'assistant', content: content, sources: sources);
}

