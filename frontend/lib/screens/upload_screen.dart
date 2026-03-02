import 'dart:async';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';
import 'subscriptions_screen.dart';

class UploadScreen extends StatefulWidget {
  const UploadScreen({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onSessionUpdated,
    required this.onSessionInvalid,
    required this.onUploadCompleted,
  });

  final ApiClient apiClient;
  final Session session;
  final ValueChanged<Session> onSessionUpdated;
  final VoidCallback onSessionInvalid;
  final ValueChanged<String> onUploadCompleted;

  @override
  State<UploadScreen> createState() => _UploadScreenState();
}

class _UploadScreenState extends State<UploadScreen> {
  bool _isUploading = false;
  bool _autoUploadOnPick = true;
  String? _uploadStatus;
  PlatformFile? _selectedFile;
  DocumentMetadata? _lastUploadedDoc;
  double _processingProgress = 0.0;
  Timer? _progressTimer;
  List<String> _detectedKeywords = [];

  @override
  void dispose() {
    _progressTimer?.cancel();
    super.dispose();
  }

  Future<T> _runWithAuthRetry<T>(Future<T> Function(String accessToken) op) async {
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

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf', 'docx', 'txt'],
      withData: kIsWeb,
    );
    if (result == null || result.files.isEmpty) return;
    setState(() {
      _selectedFile = result.files.single;
      _uploadStatus = null;
      _processingProgress = 0;
      _detectedKeywords = [];
      _lastUploadedDoc = null;
    });
    if (_autoUploadOnPick) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Picked ${result.files.single.name}. Upload started...'),
          duration: const Duration(milliseconds: 1200),
        ),
      );
      await _upload();
    }
  }

  void _startProgressAnimation() {
    _progressTimer?.cancel();
    _processingProgress = 0.04;
    _progressTimer = Timer.periodic(const Duration(milliseconds: 280), (timer) {
      if (!mounted || !_isUploading) {
        timer.cancel();
        return;
      }
      setState(() {
        if (_processingProgress < 0.88) {
          _processingProgress += 0.06;
        }
      });
    });
  }

  Future<void> _upload() async {
    if (_selectedFile == null) {
      setState(() => _uploadStatus = 'Select a document first.');
      return;
    }

    setState(() {
      _isUploading = true;
      _uploadStatus = 'Uploading and analyzing...';
      _detectedKeywords = [];
    });
    _startProgressAnimation();

    try {
      final doc = await _runWithAuthRetry(
        (token) => widget.apiClient.uploadDocument(
          accessToken: token,
          file: _selectedFile!,
        ),
      );
      if (!mounted) return;
      final retentionText = doc.retentionDays != null
          ? ' Auto-delete policy: ${doc.retentionDays} day(s).'
          : '';
      setState(() {
        _processingProgress = 1.0;
        _uploadStatus =
            'Uploaded ${doc.filename} (${doc.totalChunks} chunks).$retentionText';
        _detectedKeywords = doc.keywords;
        _lastUploadedDoc = doc;
      });
      widget.onUploadCompleted(doc.filename);
    } on ApiException catch (error) {
      if (!mounted) return;
      setState(() => _uploadStatus = error.message);
      if (error.statusCode == 402) {
        _showSubscriptionPrompt(error.message);
      }
    } catch (_) {
      if (!mounted) return;
      setState(() => _uploadStatus = 'Upload failed. Try again.');
    } finally {
      _progressTimer?.cancel();
      if (mounted) {
        setState(() => _isUploading = false);
      }
    }
  }

  void _showSubscriptionPrompt(String message) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Upgrade Required'),
        content: Text(
          '$message\n\nFree plan allows only your first document upload. Pick a plan to continue.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Later'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => SubscriptionsScreen(
                    apiClient: widget.apiClient,
                    session: widget.session,
                    onSessionUpdated: widget.onSessionUpdated,
                    onSessionInvalid: widget.onSessionInvalid,
                  ),
                ),
              );
            },
            child: const Text('View Plans'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final selectedName = _selectedFile?.name ?? 'No file selected';
    final progressCaption = _isUploading
        ? 'Extracting text, chunking, embeddings and indexing'
        : (_processingProgress >= 1
            ? 'Completed analysis'
            : 'Ready to upload and analyze');

    return Scaffold(
      body: Stack(
        children: [
          const _UploadBackground(),
          SafeArea(
            child: ListView(
              padding: const EdgeInsets.fromLTRB(18, 16, 18, 120),
              children: [
                const SizedBox(height: 4),
                GlassContainer(
                  borderRadius: 18,
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    children: [
                      _UploadSteps(
                        autoUploadOnPick: _autoUploadOnPick,
                        hasSelection: _selectedFile != null,
                        isUploading: _isUploading,
                        isDone: _processingProgress >= 1.0 &&
                            !_isUploading &&
                            (_uploadStatus ?? '').toLowerCase().startsWith('uploaded '),
                      ),
                      const SizedBox(height: 10),
                      LayoutBuilder(
                        builder: (context, constraints) {
                          final isCompact = constraints.maxWidth < 430;
                          if (isCompact) {
                            return Column(
                              children: [
                                GradientButton(
                                  label: _autoUploadOnPick
                                      ? 'Pick Document (Auto Upload)'
                                      : 'Pick Document',
                                  icon: Icons.upload_file_rounded,
                                  onPressed: _isUploading ? null : _pickFile,
                                ),
                                const SizedBox(height: 10),
                                GradientButton(
                                  label: 'Upload & Analyze',
                                  icon: Icons.bolt_rounded,
                                  onPressed: _isUploading ? null : _upload,
                                  isLoading: _isUploading,
                                ),
                              ],
                            );
                          }

                          return Row(
                            children: [
                              Expanded(
                                child: GradientButton(
                                  label: _autoUploadOnPick
                                      ? 'Pick Document (Auto Upload)'
                                      : 'Pick Document',
                                  icon: Icons.upload_file_rounded,
                                  onPressed: _isUploading ? null : _pickFile,
                                ),
                              ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: GradientButton(
                                  label: 'Upload & Analyze',
                                  icon: Icons.bolt_rounded,
                                  onPressed: _isUploading ? null : _upload,
                                  isLoading: _isUploading,
                                ),
                              ),
                            ],
                          );
                        },
                      ),
                      const SizedBox(height: 10),
                      SwitchListTile.adaptive(
                        contentPadding: EdgeInsets.zero,
                        value: _autoUploadOnPick,
                        onChanged: _isUploading
                            ? null
                            : (value) =>
                                setState(() => _autoUploadOnPick = value),
                        title: const Text('Auto upload after file pick'),
                        subtitle: const Text(
                          'Recommended: once you pick a file, upload starts immediately.',
                          style: TextStyle(fontSize: 12),
                        ),
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          const Icon(Icons.description_outlined, size: 16, color: AppColors.textMuted),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              selectedName,
                              style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 14),
                _ProcessingCard(
                  progress: _processingProgress,
                  status: _uploadStatus ?? selectedName,
                  caption: progressCaption,
                  isUploading: _isUploading,
                ),
                const SizedBox(height: 10),
                GlassContainer(
                  borderRadius: 14,
                  padding: const EdgeInsets.all(12),
                  child: const Text(
                    'Retention policy: uploaded documents are auto-cleaned by plan (Free: 3 days, Weekly: 7, Monthly: 14, Annual: 30). You will get an email reminder before deletion.',
                    style: TextStyle(fontSize: 12, color: AppColors.textMuted),
                  ),
                ),
                const SizedBox(height: 14),
                _TagSection(
                  keywords: _detectedKeywords,
                  isUploading: _isUploading,
                ),
                if (_lastUploadedDoc?.retentionExpiresAt != null) ...[
                  const SizedBox(height: 10),
                  GlassContainer(
                    borderRadius: 14,
                    padding: const EdgeInsets.all(12),
                    child: Text(
                      'Retention notice: this document will be auto-cleaned on ${_lastUploadedDoc!.retentionExpiresAt!.toLocal().toString().split(".").first} based on your current plan policy.',
                      style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ProcessingCard extends StatelessWidget {
  const _ProcessingCard({
    required this.progress,
    required this.status,
    required this.caption,
    required this.isUploading,
  });

  final double progress;
  final String status;
  final String caption;
  final bool isUploading;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Processing',
                style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16),
              ),
              const Spacer(),
              AnimatedSwitcher(
                duration: const Duration(milliseconds: 240),
                child: Text(
                  '${(progress * 100).round()}%',
                  key: ValueKey<int>((progress * 100).round()),
                  style: const TextStyle(color: AppColors.primary, fontWeight: FontWeight.w700),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(10),
            child: TweenAnimationBuilder<double>(
              tween: Tween<double>(begin: 0, end: progress),
              duration: const Duration(milliseconds: 320),
              builder: (context, value, _) {
                return LinearProgressIndicator(
                  value: value.clamp(0, 1),
                  minHeight: 9,
                  backgroundColor: Colors.white10,
                  valueColor: const AlwaysStoppedAnimation(AppColors.primary),
                );
              },
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              if (isUploading)
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              else
                const Icon(Icons.check_circle_outline, size: 16, color: AppColors.accent),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  caption,
                  style: const TextStyle(color: AppColors.textMuted),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            status,
            style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}

class _TagSection extends StatelessWidget {
  const _TagSection({
    required this.keywords,
    required this.isUploading,
  });

  final List<String> keywords;
  final bool isUploading;

  @override
  Widget build(BuildContext context) {
    final fallback = isUploading
        ? const ['Detecting keywords...']
        : const ['No tags yet. Upload a document to generate keywords.'];
    final tags = keywords.isEmpty ? fallback : keywords;

    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: const [
              Text(
                'Intelligent Tagging',
                style: TextStyle(fontWeight: FontWeight.w700),
              ),
              Spacer(),
              Icon(Icons.sell_outlined, color: AppColors.primary, size: 18),
            ],
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: tags
                .map(
                  (text) => Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(14),
                      color: AppColors.surfaceDark.withValues(alpha: 0.7),
                      border: Border.all(color: AppColors.glassBorder),
                    ),
                    child: Text(
                      text,
                      style: TextStyle(
                        fontSize: 12,
                        color: text.contains('No tags') ? AppColors.textMuted : Colors.white,
                      ),
                    ),
                  ),
                )
                .toList(),
          ),
        ],
      ),
    );
  }
}

class _UploadSteps extends StatelessWidget {
  const _UploadSteps({
    required this.autoUploadOnPick,
    required this.hasSelection,
    required this.isUploading,
    required this.isDone,
  });

  final bool autoUploadOnPick;
  final bool hasSelection;
  final bool isUploading;
  final bool isDone;

  @override
  Widget build(BuildContext context) {
    final step1Done = hasSelection || isUploading || isDone;
    final step2Done = isUploading || isDone;
    final step3Done = isDone;
    final step2Label = autoUploadOnPick ? 'Upload (Auto)' : 'Upload';

    return Column(
      children: [
        Row(
          children: [
            _StepDot(done: step1Done, index: 1),
            Expanded(
              child: Divider(
                color: step1Done ? AppColors.primary : Colors.white24,
                thickness: 1,
              ),
            ),
            _StepDot(done: step2Done, index: 2),
            Expanded(
              child: Divider(
                color: step2Done ? AppColors.primary : Colors.white24,
                thickness: 1,
              ),
            ),
            _StepDot(done: step3Done, index: 3),
          ],
        ),
        const SizedBox(height: 6),
        const Row(
          children: [
            Expanded(
              child: Text(
                'Pick',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 11, color: AppColors.textMuted),
              ),
            ),
            Expanded(
              child: SizedBox(),
            ),
            Expanded(
              child: SizedBox(),
            ),
          ],
        ),
        Row(
          children: [
            const Expanded(
              child: SizedBox(),
            ),
            Expanded(
              child: Text(
                step2Label,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 11, color: AppColors.textMuted),
              ),
            ),
            const Expanded(
              child: Text(
                'Ready',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 11, color: AppColors.textMuted),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _StepDot extends StatelessWidget {
  const _StepDot({required this.done, required this.index});

  final bool done;
  final int index;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 22,
      height: 22,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: done ? AppColors.primary : Colors.white12,
        border: Border.all(
          color: done ? AppColors.primary : Colors.white24,
        ),
      ),
      alignment: Alignment.center,
      child: done
          ? const Icon(Icons.check, size: 13, color: Colors.white)
          : Text(
              '$index',
              style: const TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w700,
                color: AppColors.textMuted,
              ),
            ),
    );
  }
}

class _UploadBackground extends StatelessWidget {
  const _UploadBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF0B101B), AppColors.surfaceDark],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            bottom: -60,
            right: -40,
            child: _GlowOrb(color: AppColors.primary.withValues(alpha: 0.2)),
          ),
          Positioned(
            top: 120,
            left: -40,
            child: _GlowOrb(color: AppColors.primary.withValues(alpha: 0.08)),
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
      height: 180,
      width: 180,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [
          BoxShadow(
            color: color,
            blurRadius: 120,
            spreadRadius: 30,
          ),
        ],
      ),
    );
  }
}
