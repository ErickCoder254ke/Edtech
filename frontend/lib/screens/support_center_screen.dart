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
          title: const Text('Support Center'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'About'),
              Tab(text: 'Help'),
              Tab(text: 'Contact'),
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
          child: TabBarView(
            children: [
              _AboutTab(),
              _HelpTab(),
              _ContactTab(email: _email, phone: _phone),
            ],
          ),
        ),
      ),
    );
  }
}

class _AboutTab extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
      children: const [
        _HeroPanel(
          title: 'Exam OS by EdTech Intelligence',
          subtitle:
              'A focused learning engine for institutions, teachers, and students who need reliable assessments fast.',
        ),
        SizedBox(height: 12),
        _InfoCard(
          title: 'Our Mission',
          body:
              'We help educators turn course materials into structured assessments, revision packs, and guided learning artifacts with strong accuracy and clean formatting.',
          icon: Icons.flag_rounded,
        ),
        SizedBox(height: 10),
        _InfoCard(
          title: 'What Makes Exam OS Different',
          body:
              'Exam OS is built for academic workflows first: upload-to-output speed, clear mark schemes, quiz/exam modes, and consistent document quality for real classrooms.',
          icon: Icons.workspace_premium_rounded,
        ),
        SizedBox(height: 10),
        _InfoCard(
          title: 'Trust & Security',
          body:
              'We continuously harden auth, account controls, and reset flows while preserving practical UX so institutions can deploy confidently.',
          icon: Icons.verified_user_rounded,
        ),
      ],
    );
  }
}

class _HelpTab extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
      children: const [
        _InfoCard(
          title: 'Getting Started',
          body:
              '1) Upload one clean source document.\n2) Open Generation Lab.\n3) Pick Summary, Concepts, Quiz, or Exam.\n4) Export and share.',
          icon: Icons.play_circle_fill_rounded,
        ),
        SizedBox(height: 10),
        _InfoCard(
          title: 'Common Upload Issues',
          body:
              'Use readable PDF/DOCX/TXT files. If upload times out, retry on stable internet and reduce file size where possible.',
          icon: Icons.upload_file_rounded,
        ),
        SizedBox(height: 10),
        _InfoCard(
          title: 'Login & Account Recovery',
          body:
              'Use Forgot Password from sign in. Reset links are time-bound and single-use for account safety.',
          icon: Icons.lock_reset_rounded,
        ),
        SizedBox(height: 10),
        _InfoCard(
          title: 'Billing & Plans',
          body:
              'Your generation limits are tracked server-side. Deleting old content does not reset consumed quota.',
          icon: Icons.receipt_long_rounded,
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
    if (digits.startsWith('254')) {
      return digits;
    }
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
        const _HeroPanel(
          title: 'Talk to Exam OS Support',
          subtitle:
              'For onboarding, technical issues, subscription assistance, or deployment guidance, contact us directly.',
        ),
        const SizedBox(height: 12),
        _InfoCard(
          title: 'Support Email',
          body: email,
          icon: Icons.email_rounded,
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: () => _openEmail(context),
            icon: const Icon(Icons.forward_to_inbox_rounded),
            label: const Text('Email Support'),
          ),
        ),
        const SizedBox(height: 10),
        _InfoCard(
          title: 'Support Phone',
          body: phone,
          icon: Icons.phone_rounded,
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            onPressed: () => _openWhatsApp(context),
            icon: const Icon(Icons.chat_bubble_rounded),
            label: const Text('Chat on WhatsApp'),
          ),
        ),
        const SizedBox(height: 10),
        const _InfoCard(
          title: 'Support Hours',
          body: 'Mon - Sat, 8:00 AM - 8:00 PM (EAT)',
          icon: Icons.schedule_rounded,
        ),
      ],
    );
  }
}

class _HeroPanel extends StatelessWidget {
  const _HeroPanel({required this.title, required this.subtitle});

  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 20,
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 8),
          Text(
            subtitle,
            style: const TextStyle(color: AppColors.textMuted, height: 1.45),
          ),
        ],
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
            width: 36,
            height: 36,
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
                const SizedBox(height: 4),
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
