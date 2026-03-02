import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class TermsConditionsScreen extends StatelessWidget {
  const TermsConditionsScreen({super.key});
  static const String _termsVersion = 'Terms v2.0';
  static const String _effectiveDate = 'March 2, 2026';

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
            _TermsMetaRow(),
            SizedBox(height: 10),
            _TermsHero(),
            SizedBox(height: 12),
            _SectionCard(
              title: '1. Acceptable Use',
              body:
                  'Use Exam OS for lawful educational workflows. You must not upload harmful, infringing, abusive, or unlawful content.',
              icon: Icons.gavel_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '2. Accounts, Roles, and Access',
              body:
                  'You are responsible for actions performed through your account. Keep credentials secure. Teacher features may require verification before class creation.',
              icon: Icons.manage_accounts_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '3. Generation Output Responsibility',
              body:
                  'Generated content is assistive and must be reviewed before publishing, grading, or classroom use. You remain responsible for academic correctness and compliance.',
              icon: Icons.auto_fix_high_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '4. Payments, Escrow, and Withdrawals',
              body:
                  'Class payments may be held in escrow until class completion under platform policy. Platform fee percentages and payout rules are enforced server-side.',
              icon: Icons.account_balance_wallet_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '5. Data Retention Policy',
              body:
                  'Uploaded documents and derived artifacts may be auto-cleaned by plan retention windows. Reminder notifications may be sent before scheduled cleanup.',
              icon: Icons.auto_delete_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '6. Availability and Reliability',
              body:
                  'We target high availability but cannot guarantee uninterrupted service. Features and limits may change to improve performance, security, and legal compliance.',
              icon: Icons.cloud_done_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '7. Enforcement and Termination',
              body:
                  'Accounts may be limited or terminated for abuse, fraud, policy violations, or payment misuse. Enforcement decisions prioritize user safety and system integrity.',
              icon: Icons.policy_rounded,
            ),
            SizedBox(height: 10),
            _SectionCard(
              title: '8. Consent',
              body:
                  'By continuing to use Exam OS, you agree to these terms. If you disagree, discontinue use and request account deletion from support.',
              icon: Icons.check_circle_rounded,
            ),
          ],
        ),
      ),
    );
  }
}

class _TermsHero extends StatelessWidget {
  const _TermsHero();

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
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Exam OS Legal Terms',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 8),
            const Text(
              'These terms govern account use, generated content, payments, retention, and platform integrity controls.',
              style: TextStyle(color: AppColors.textMuted, height: 1.45),
            ),
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AppColors.surfaceDark.withValues(alpha: 0.55),
                borderRadius: BorderRadius.circular(20),
              ),
              child: const Text(
                'Effective Date: March 2, 2026',
                style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TermsMetaRow extends StatelessWidget {
  const _TermsMetaRow();

  @override
  Widget build(BuildContext context) {
    return Row(
      children: const [
        _TermsMetaChip(label: TermsConditionsScreen._termsVersion),
        SizedBox(width: 8),
        _TermsMetaChip(label: 'Effective ${TermsConditionsScreen._effectiveDate}'),
      ],
    );
  }
}

class _TermsMetaChip extends StatelessWidget {
  const _TermsMetaChip({required this.label});

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
                Text(
                  title,
                  style: const TextStyle(fontWeight: FontWeight.w800),
                ),
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
