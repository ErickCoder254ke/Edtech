import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class PrivateTutorsScreen extends StatefulWidget {
  const PrivateTutorsScreen({
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
  State<PrivateTutorsScreen> createState() => _PrivateTutorsScreenState();
}

class _PrivateTutorsScreenState extends State<PrivateTutorsScreen> {
  bool _loading = true;
  String? _error;
  String _city = '';
  final _cityController = TextEditingController();
  List<PrivateTutorProfile> _items = [];
  final Set<String> _booking = <String>{};

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _cityController.dispose();
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

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final tutors = await _runWithAuthRetry(
        (token) => widget.apiClient.listPrivateTutors(
          accessToken: token,
          limit: 40,
          city: _city.trim().isEmpty ? null : _city.trim(),
        ),
      );
      if (!mounted) return;
      setState(() => _items = tutors);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Unable to load tutor directory.');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _book(PrivateTutorProfile tutor) async {
    if (_booking.contains(tutor.id)) return;
    setState(() => _booking.add(tutor.id));
    try {
      final intent = await _runWithAuthRetry(
        (token) => widget.apiClient.privateTutorBookingIntent(
          accessToken: token,
          tutorId: tutor.id,
        ),
      );
      final deepUri = Uri.tryParse(intent.deepLink);
      if (deepUri != null && await canLaunchUrl(deepUri)) {
        await launchUrl(deepUri, mode: LaunchMode.externalApplication);
      } else {
        if (!mounted) return;
        await _showInstallPrompt(intent.playstoreUrl);
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => _booking.remove(tutor.id));
    }
  }

  Future<void> _showInstallPrompt(String playstoreUrl) async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('LocalPro KE Required'),
        content: const Text(
          'To complete this private-class booking, install LocalPro KE from Google Play.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              Navigator.of(ctx).pop();
              final uri = Uri.tryParse(playstoreUrl);
              if (uri != null) {
                await launchUrl(uri, mode: LaunchMode.externalApplication);
              }
            },
            child: const Text('Install App'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Private Tutors'),
        actions: [
          IconButton(onPressed: _load, icon: const Icon(Icons.refresh_rounded)),
        ],
      ),
      body: Stack(
        children: [
          const _Backdrop(),
          SafeArea(
            child: RefreshIndicator(
              onRefresh: _load,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 24),
                children: [
                  GlassContainer(
                    borderRadius: 18,
                    padding: const EdgeInsets.all(12),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _cityController,
                            decoration: const InputDecoration(
                              hintText: 'Filter by town (e.g. Nairobi)',
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        FilledButton(
                          onPressed: () {
                            _city = _cityController.text.trim();
                            _load();
                          },
                          child: const Text('Search'),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 10),
                  if (_loading)
                    const _LoadingTile()
                  else if (_error != null)
                    _ErrorTile(message: _error!)
                  else if (_items.isEmpty)
                    const _EmptyTile()
                  else
                    ..._items.map((tutor) => Padding(
                          padding: const EdgeInsets.only(bottom: 10),
                          child: _TutorCard(
                            tutor: tutor,
                            booking: _booking.contains(tutor.id),
                            onBook: () => _book(tutor),
                          ),
                        )),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _TutorCard extends StatelessWidget {
  const _TutorCard({
    required this.tutor,
    required this.booking,
    required this.onBook,
  });

  final PrivateTutorProfile tutor;
  final bool booking;
  final VoidCallback onBook;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 24,
                backgroundColor: AppColors.primary.withValues(alpha: 0.2),
                backgroundImage: tutor.photoUrl != null && tutor.photoUrl!.trim().isNotEmpty
                    ? NetworkImage(tutor.photoUrl!)
                    : null,
                child: tutor.photoUrl == null || tutor.photoUrl!.isEmpty
                    ? Text(
                        tutor.providerName.isEmpty ? 'T' : tutor.providerName[0].toUpperCase(),
                        style: const TextStyle(fontWeight: FontWeight.w800, color: AppColors.primary),
                      )
                    : null,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(tutor.providerName, style: const TextStyle(fontWeight: FontWeight.w800)),
                    Text(
                      tutor.headline,
                      style: const TextStyle(color: AppColors.textMuted),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: tutor.availableNow
                      ? Colors.green.withValues(alpha: 0.18)
                      : Colors.white.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  tutor.availableNow ? 'AVAILABLE' : 'SCHEDULED',
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    color: tutor.availableNow ? Colors.greenAccent : AppColors.textMuted,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          if (tutor.bio.trim().isNotEmpty)
            Text(
              tutor.bio,
              maxLines: 3,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: AppColors.textMuted),
            ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: [
              _Tag(text: 'KES ${tutor.priceKes.toStringAsFixed(0)} ${tutor.priceUnit}'),
              _Tag(text: '${tutor.experienceYears} yrs exp'),
              if (tutor.city.isNotEmpty) _Tag(text: tutor.city),
            ],
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: booking ? null : onBook,
              icon: booking
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.open_in_new_rounded),
              label: const Text('Book on LocalPro KE'),
            ),
          ),
        ],
      ),
    );
  }
}

class _Tag extends StatelessWidget {
  const _Tag({required this.text});
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

class _Backdrop extends StatelessWidget {
  const _Backdrop();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF051226), Color(0xFF091024), Color(0xFF131026)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
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
          SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
          SizedBox(width: 10),
          Text('Loading private tutors...'),
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
          Expanded(child: Text(message, style: const TextStyle(color: Colors.redAccent))),
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
          Text('No tutors found', style: TextStyle(fontWeight: FontWeight.w700)),
          SizedBox(height: 4),
          Text(
            'Try a different town filter or refresh shortly.',
            style: TextStyle(color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }
}
