import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class PrivacyPolicyScreen extends StatelessWidget {
  const PrivacyPolicyScreen({super.key});

  static const String _version = 'Privacy v1.0';
  static const String _effectiveDate = 'March 2, 2026';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Privacy Policy')),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
          children: const [
            _MetaRow(),
            SizedBox(height: 10),
            _Hero(),
            SizedBox(height: 12),
            _Section(
              title: '1. Data We Process',
              body:
                  'We process account details, uploaded learning materials, generation requests, class/payment events, and technical diagnostics required for reliable service delivery.',
              icon: Icons.dataset_rounded,
            ),
            SizedBox(height: 10),
            _Section(
              title: '2. Why We Process Data',
              body:
                  'To authenticate users, generate requested outputs, support subscriptions/classes, prevent abuse, and maintain operational reliability.',
              icon: Icons.track_changes_rounded,
            ),
            SizedBox(height: 10),
            _Section(
              title: '3. Retention Windows',
              body:
                  'Documents and derived artifacts may be auto-cleaned based on plan retention policy. You may receive reminders before scheduled cleanup.',
              icon: Icons.auto_delete_rounded,
            ),
            SizedBox(height: 10),
            _Section(
              title: '4. Security Controls',
              body:
                  'We use token-based auth, scoped access checks, rate limits, and audit-oriented diagnostics. Sensitive credentials should be kept in environment configuration only.',
              icon: Icons.security_rounded,
            ),
            SizedBox(height: 10),
            _Section(
              title: '5. Third-Party Processors',
              body:
                  'Depending on enabled features, processing may involve payment providers, notification services, Cloudinary, and email providers.',
              icon: Icons.hub_rounded,
            ),
            SizedBox(height: 10),
            _Section(
              title: '6. Your Choices',
              body:
                  'You can update profile details, request support assistance, and choose whether to continue using the service under these privacy terms.',
              icon: Icons.tune_rounded,
            ),
          ],
        ),
      ),
    );
  }
}

class _MetaRow extends StatelessWidget {
  const _MetaRow();

  @override
  Widget build(BuildContext context) {
    return Row(
      children: const [
        _MetaChip(label: PrivacyPolicyScreen._version),
        SizedBox(width: 8),
        _MetaChip(label: 'Effective ${PrivacyPolicyScreen._effectiveDate}'),
      ],
    );
  }
}

class _MetaChip extends StatelessWidget {
  const _MetaChip({required this.label});
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: AppColors.surfaceDark.withValues(alpha: 0.65),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: AppColors.glassBorder),
      ),
      child: Text(
        label,
        style: const TextStyle(fontSize: 11, color: AppColors.textMuted, fontWeight: FontWeight.w700),
      ),
    );
  }
}

class _Hero extends StatelessWidget {
  const _Hero();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        gradient: LinearGradient(
          colors: [
            AppColors.primary.withValues(alpha: 0.25),
            AppColors.accent.withValues(alpha: 0.16),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: GlassContainer(
        borderRadius: 22,
        padding: const EdgeInsets.all(18),
        child: const Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Exam OS Privacy Policy',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900),
            ),
            SizedBox(height: 8),
            Text(
              'This policy describes how data is used to run generation, classes, payments, and support workflows safely.',
              style: TextStyle(color: AppColors.textMuted, height: 1.45),
            ),
          ],
        ),
      ),
    );
  }
}

class _Section extends StatelessWidget {
  const _Section({
    required this.title,
    required this.body,
    required this.icon,
  });

  final String title;
  final String body;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(14),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            height: 38,
            width: 38,
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: AppColors.primary, size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(fontWeight: FontWeight.w800)),
                const SizedBox(height: 5),
                Text(
                  body,
                  style: const TextStyle(color: AppColors.textMuted, height: 1.45),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
