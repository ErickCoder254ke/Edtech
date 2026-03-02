import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../config/app_config.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';

class SupportCenterScreen extends StatefulWidget {
  const SupportCenterScreen({
    super.key,
    required this.apiClient,
    this.initialTab = 0,
  });

  final ApiClient apiClient;
  final int initialTab;

  @override
  State<SupportCenterScreen> createState() => _SupportCenterScreenState();
}

class _SupportCenterScreenState extends State<SupportCenterScreen> {
  static const String _contentVersion = 'Support Pack v2.0';
  static const String _lastUpdated = 'March 2, 2026';
  String _email = AppConfig.supportEmailFallback;
  String _phone = AppConfig.supportPhoneFallback;

  @override
  void initState() {
    super.initState();
    _loadSupportContact();
  }

  Future<void> _loadSupportContact() async {
    try {
      final support = await widget.apiClient.getSupportContact();
      if (!mounted) return;
      setState(() {
        _email = (support['email'] ?? '').trim().isEmpty
            ? AppConfig.supportEmailFallback
            : support['email']!.trim();
        _phone = (support['phone'] ?? '').trim().isEmpty
            ? AppConfig.supportPhoneFallback
            : support['phone']!.trim();
      });
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      initialIndex: widget.initialTab.clamp(0, 2).toInt(),
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Support Hub'),
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.auto_awesome_rounded), text: 'About'),
              Tab(icon: Icon(Icons.lightbulb_rounded), text: 'Help'),
              Tab(icon: Icon(Icons.support_agent_rounded), text: 'Contact'),
            ],
          ),
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
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 0),
                child: Row(
                  children: [
                    _MetaChip(label: _contentVersion),
                    const SizedBox(width: 8),
                    _MetaChip(label: 'Updated $_lastUpdated'),
                  ],
                ),
              ),
              Expanded(
                child: TabBarView(
                  children: [
                    _AboutTab(),
                    _HelpTab(),
                    _ContactTab(email: _email, phone: _phone),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
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

class _AboutTab extends StatelessWidget {
  final List<_Pillar> _pillars = const [
    _Pillar(
      icon: Icons.bolt_rounded,
      title: 'Speed With Structure',
      body:
          'Exam OS is built to move from source notes to classroom-ready assessments quickly, while preserving clean question structure and mark alignment.',
    ),
    _Pillar(
      icon: Icons.verified_user_rounded,
      title: 'Trust & Governance',
      body:
          'Role-based access, teacher verification, class payment controls, and operational diagnostics are built into the core workflow.',
    ),
    _Pillar(
      icon: Icons.model_training_rounded,
      title: 'Practical AI Layer',
      body:
          'Generation quality is tuned for real school use cases: exam drafts, mark schemes, summaries, and curriculum-driven outputs.',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
      children: [
        const _SpotlightCard(
          title: 'Exam OS',
          subtitle:
              'An academic operations platform for teachers and students: generate, teach, schedule, pay, and monitor from one place.',
          accent: 'Built for production school workflows',
        ),
        const SizedBox(height: 12),
        ..._pillars.map(
          (item) => Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: _InfoCard(title: item.title, body: item.body, icon: item.icon),
          ),
        ),
        const SizedBox(height: 2),
        const _InfoCard(
          title: 'Version Scope',
          body:
              'This release includes async generation jobs, teacher verification, class payment flows, shared notes, and admin-level reliability controls.',
          icon: Icons.change_circle_rounded,
        ),
      ],
    );
  }
}

class _HelpTab extends StatelessWidget {
  final List<_FaqItem> _faqs = const [
    _FaqItem(
      q: 'Why does generation sometimes queue?',
      a:
          'Generation runs through background workers to keep requests reliable under load. Use My Jobs to track queued, processing, and completed states.',
    ),
    _FaqItem(
      q: 'Why did my document disappear?',
      a:
          'Documents follow retention by plan (Free 3 days, Weekly 7, Monthly 14, Annual 30). You receive reminder emails before scheduled cleanup.',
    ),
    _FaqItem(
      q: 'Why can class payment show pending?',
      a:
          'STK callbacks can be delayed. Wait briefly, refresh class status, and retry only if payment has not reflected. Duplicate payment creation is protected server-side.',
    ),
    _FaqItem(
      q: 'Can I use another person’s phone to pay?',
      a:
          'Yes. When paying, you can enter a new number or pick a saved one. This supports parent/guardian payment scenarios.',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
      children: [
        const _SpotlightCard(
          title: 'Quick Start',
          subtitle:
              'Upload a document, generate content, review output, then export or assign. Keep prompts specific for best quality.',
          accent: 'Recommended: start with one clean source file',
        ),
        const SizedBox(height: 12),
        const _InfoCard(
          title: 'Generation Best Practice',
          body:
              'Use explicit instructions (section style, mark ranges, command verbs, and exam title/school metadata) to reduce revisions and improve first-pass output.',
          icon: Icons.auto_fix_high_rounded,
        ),
        const SizedBox(height: 10),
        const _InfoCard(
          title: 'Upload Reliability',
          body:
              'Use readable PDF/DOCX/TXT files. If extraction fails, upload a cleaner source file or split very large notes into smaller files.',
          icon: Icons.file_upload_rounded,
        ),
        const SizedBox(height: 10),
        GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'FAQ',
                style: TextStyle(fontWeight: FontWeight.w800, fontSize: 15),
              ),
              const SizedBox(height: 8),
              ..._faqs.map(
                (item) => ExpansionTile(
                  tilePadding: EdgeInsets.zero,
                  childrenPadding: const EdgeInsets.only(bottom: 8),
                  iconColor: AppColors.primary,
                  collapsedIconColor: AppColors.textMuted,
                  title: Text(item.q, style: const TextStyle(fontWeight: FontWeight.w700)),
                  children: [
                    Align(
                      alignment: Alignment.centerLeft,
                      child: Text(
                        item.a,
                        style: const TextStyle(color: AppColors.textMuted, height: 1.45),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _ContactTab extends StatelessWidget {
  const _ContactTab({required this.email, required this.phone});

  final String email;
  final String phone;

  String _toWhatsAppNumber(String input) {
    final digits = input.replaceAll(RegExp(r'[^0-9]'), '');
    if (digits.startsWith('0') && digits.length >= 10) {
      return '254${digits.substring(1)}';
    }
    if (digits.startsWith('254')) return digits;
    return digits;
  }

  Future<void> _openWhatsApp(BuildContext context) async {
    final number = _toWhatsAppNumber(phone);
    if (number.isEmpty) return;
    final text = Uri.encodeComponent('Hi Exam OS Support, I need help.');
    final uri = Uri.parse('https://wa.me/$number?text=$text');
    final launched = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!launched && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not open WhatsApp on this device.')),
      );
    }
  }

  Future<void> _openEmail(BuildContext context) async {
    final address = email.trim();
    if (address.isEmpty) return;
    final uri = Uri(
      scheme: 'mailto',
      path: address,
      queryParameters: {
        'subject': 'Exam OS Support Request',
      },
    );
    final launched = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!launched && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not open email app on this device.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
      children: [
        const _SpotlightCard(
          title: 'Contact Support',
          subtitle:
              'For technical incidents, billing questions, onboarding, and production issues, reach out directly.',
          accent: 'Fastest route: WhatsApp for urgent issues',
        ),
        const SizedBox(height: 12),
        _InfoCard(
          title: 'Email',
          body: email,
          icon: Icons.alternate_email_rounded,
        ),
        const SizedBox(height: 10),
        _InfoCard(
          title: 'Phone / WhatsApp',
          body: phone,
          icon: Icons.call_rounded,
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => _openEmail(context),
                icon: const Icon(Icons.mark_email_unread_rounded),
                label: const Text('Email'),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () => _openWhatsApp(context),
                icon: const Icon(Icons.chat_rounded),
                label: const Text('WhatsApp'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        const _InfoCard(
          title: 'Support Window',
          body:
              'Mon - Sat • 8:00 AM - 8:00 PM (EAT)\nCritical production incidents are prioritized by severity.',
          icon: Icons.schedule_rounded,
        ),
      ],
    );
  }
}

class _SpotlightCard extends StatelessWidget {
  const _SpotlightCard({
    required this.title,
    required this.subtitle,
    required this.accent,
  });

  final String title;
  final String subtitle;
  final String accent;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        gradient: LinearGradient(
          colors: [
            AppColors.primary.withValues(alpha: 0.25),
            AppColors.accent.withValues(alpha: 0.18),
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
            Text(
              title,
              style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 8),
            Text(
              subtitle,
              style: const TextStyle(color: AppColors.textMuted, height: 1.45),
            ),
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AppColors.surfaceDark.withValues(alpha: 0.55),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Text(
                accent,
                style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({
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
            width: 38,
            height: 38,
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
                const SizedBox(height: 4),
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

class _Pillar {
  const _Pillar({
    required this.icon,
    required this.title,
    required this.body,
  });

  final IconData icon;
  final String title;
  final String body;
}

class _FaqItem {
  const _FaqItem({required this.q, required this.a});
  final String q;
  final String a;
}
