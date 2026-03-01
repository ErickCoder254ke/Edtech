import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class TermsConditionsScreen extends StatelessWidget {
  const TermsConditionsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Terms & Conditions')),
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
            _SectionCard(
              title: 'Exam OS Terms',
              body:
                  'By using Exam OS, you agree to use the platform responsibly for educational and professional purposes. '
                  'Do not upload unlawful, harmful, or infringing content.',
              icon: Icons.description_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Account & Security',
              body:
                  'You are responsible for account credentials and activity under your account. '
                  'Use strong passwords and protect your sign-in devices.',
              icon: Icons.shield_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Billing, Plans, and Quotas',
              body:
                  'Plan limits and subscription quotas are enforced server-side. '
                  'Deleting documents or generations does not restore consumed usage. '
                  'Charges and renewal behavior are defined by your selected plan and payment confirmation.',
              icon: Icons.receipt_long_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Content Responsibility',
              body:
                  'Generated outputs are assistive and should be reviewed by the user before publishing, grading, or distribution. '
                  'You remain responsible for academic and instructional correctness.',
              icon: Icons.rule_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Data & Privacy',
              body:
                  'Exam OS processes uploaded materials to provide generation features and account functionality. '
                  'Access controls and token-based authentication are applied to protect user data.',
              icon: Icons.lock_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Service Availability',
              body:
                  'We aim for high availability but do not guarantee uninterrupted service. '
                  'Features may change over time to improve reliability, compliance, and product quality.',
              icon: Icons.cloud_done_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: 'Acceptance',
              body:
                  'Continuing to use Exam OS means you accept these terms. '
                  'If you do not agree, discontinue use and delete your account from the profile section.',
              icon: Icons.check_circle_rounded,
            ),
          ],
        ),
      ),
    );
  }
}

class _SectionCard extends StatelessWidget {
  const _SectionCard({
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
            height: 36,
            width: 36,
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
                Text(
                  title,
                  style: const TextStyle(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 5),
                Text(
                  body,
                  style: const TextStyle(color: AppColors.textMuted, height: 1.4),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
