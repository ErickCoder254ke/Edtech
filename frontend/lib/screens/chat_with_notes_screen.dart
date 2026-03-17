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

  @override
  void initState() {
    super.initState();
    _session = widget.session;
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
                    Expanded(
                      child: GlassContainer(
                        borderRadius: 14,
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                        child: TextField(
                          controller: _controller,
                          minLines: 1,
                          maxLines: 4,
                          style: const TextStyle(color: Colors.white),
                          cursorColor: AppColors.accent,
                          textInputAction: TextInputAction.send,
                          onSubmitted: (_) => _send(),
                          decoration: const InputDecoration(
                            border: InputBorder.none,
                            hintText: 'Ask about a concept from the selected notes...',
                            hintStyle: TextStyle(color: Colors.white54),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
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

