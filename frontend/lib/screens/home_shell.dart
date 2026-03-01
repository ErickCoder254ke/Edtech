import 'dart:async';

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import 'dashboard_screen.dart';
import 'classes_screen.dart';
import 'admin_dashboard_screen.dart';
import 'exam_configurator_screen.dart';
import 'jobs_screen.dart';
import 'library_screen.dart';
import 'notifications_screen.dart';
import 'profile_screen.dart';
import 'private_tutors_screen.dart';
import 'subscriptions_screen.dart';
import 'support_center_screen.dart';
import 'terms_conditions_screen.dart';
import 'topic_suggestions_screen.dart';
import 'topic_moderation_screen.dart';
import 'upload_screen.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({
    super.key,
    required this.apiClient,
    required this.session,
    required this.onLogout,
    required this.onSessionUpdated,
  });

  final ApiClient apiClient;
  final Session session;
  final VoidCallback onLogout;
  final ValueChanged<Session> onSessionUpdated;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();
  bool _hasDocuments = true;
  bool _loadingCoachState = true;
  String? _uploadCompleteNote;
  Timer? _uploadCompleteTimer;
  int _flaggedTopicCount = 0;

  String _titleForIndex(int index) {
    switch (index) {
      case 0:
        return 'Dashboard';
      case 1:
        return 'Library';
      case 2:
        return 'Upload';
      case 3:
        return 'Generation Lab';
      case 4:
        return 'Topic Board';
      default:
        return 'Exam OS';
    }
  }

  void _openProfilePage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ProfileScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
          onLogout: widget.onLogout,
        ),
      ),
    );
  }

  void _openSubscriptionsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => SubscriptionsScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  void _openClassesPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ClassesScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  void _openJobsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => JobsScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  void _openNotificationsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => NotificationsScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  void _openPrivateTutorsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => PrivateTutorsScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  void _openTopicModerationPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => TopicModerationScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    ).then((_) => _loadTopicModerationBadge());
  }

  void _openAdminDashboardPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AdminDashboardScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    _loadCoachState();
    _loadTopicModerationBadge();
  }

  @override
  void didUpdateWidget(covariant HomeShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadCoachState();
      _loadTopicModerationBadge();
    }
  }

  Future<T> _runWithAuthRetry<T>(
    Future<T> Function(String accessToken) op,
  ) async {
    try {
      return await op(widget.session.accessToken);
    } on ApiException catch (e) {
      if (e.statusCode != 401) rethrow;
      final refreshed = await widget.apiClient.refreshTokens(
        refreshToken: widget.session.refreshToken,
      );
      final nextSession = refreshed.toSession();
      widget.onSessionUpdated(nextSession);
      return await op(nextSession.accessToken);
    }
  }

  Future<void> _loadCoachState() async {
    setState(() => _loadingCoachState = true);
    try {
      final docs = await _runWithAuthRetry(
        (token) => widget.apiClient.listDocuments(token, limit: 1),
      );
      if (!mounted) return;
      setState(() => _hasDocuments = docs.isNotEmpty);
    } catch (_) {
      if (!mounted) return;
      setState(() => _hasDocuments = true);
    } finally {
      if (mounted) setState(() => _loadingCoachState = false);
    }
  }

  Future<void> _loadTopicModerationBadge() async {
    if (widget.session.user.role.toLowerCase() != 'teacher') {
      if (mounted) setState(() => _flaggedTopicCount = 0);
      return;
    }
    try {
      final flagged = await _runWithAuthRetry(
        (token) => widget.apiClient.listFlaggedTopics(accessToken: token, limit: 120),
      );
      if (!mounted) return;
      setState(() => _flaggedTopicCount = flagged.length);
    } catch (_) {
      if (!mounted) return;
      setState(() => _flaggedTopicCount = 0);
    }
  }

  String _shortName(String raw) {
    if (raw.length <= 18) return raw;
    return '${raw.substring(0, 15)}...';
  }

  void _onUploadCompleted(String filename) {
    if (!mounted) return;
    _uploadCompleteTimer?.cancel();
    setState(() {
      _hasDocuments = true;
      _uploadCompleteNote =
          'Upload done: ${_shortName(filename)}. Use Generation Engine.';
    });
    _uploadCompleteTimer = Timer(const Duration(seconds: 6), () {
      if (!mounted) return;
      setState(() => _uploadCompleteNote = null);
    });
  }

  @override
  void dispose() {
    _uploadCompleteTimer?.cancel();
    super.dispose();
  }

  void _openSupportPage(int tab) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) =>
            SupportCenterScreen(apiClient: widget.apiClient, initialTab: tab),
      ),
    );
  }

  void _openTermsPage() {
    Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => const TermsConditionsScreen()));
  }

  @override
  Widget build(BuildContext context) {
    final screens = [
      DashboardScreen(
        apiClient: widget.apiClient,
        session: widget.session,
        onSessionUpdated: widget.onSessionUpdated,
        onSessionInvalid: widget.onLogout,
        onGoToUpload: () => setState(() => _index = 2),
        onGoToExamLab: () => setState(() => _index = 3),
      ),
      LibraryScreen(
        apiClient: widget.apiClient,
        session: widget.session,
        onSessionUpdated: widget.onSessionUpdated,
        onSessionInvalid: widget.onLogout,
      ),
      UploadScreen(
        apiClient: widget.apiClient,
        session: widget.session,
        onSessionUpdated: widget.onSessionUpdated,
        onSessionInvalid: widget.onLogout,
        onUploadCompleted: _onUploadCompleted,
      ),
      ExamConfiguratorScreen(
        apiClient: widget.apiClient,
        session: widget.session,
        onSessionUpdated: widget.onSessionUpdated,
        onSessionInvalid: widget.onLogout,
      ),
      TopicSuggestionsScreen(
        apiClient: widget.apiClient,
        session: widget.session,
        onSessionUpdated: widget.onSessionUpdated,
        onSessionInvalid: widget.onLogout,
      ),
    ];

    return Stack(
      children: [
        Scaffold(
          key: _scaffoldKey,
          drawer: Drawer(
            backgroundColor: AppColors.surfaceDark,
            child: SafeArea(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(12, 12, 12, 20),
                children: [
                  _MenuProfileCard(user: widget.session.user),
                  const SizedBox(height: 14),
                  const _MenuSectionTitle('Shortcuts'),
                  _MenuNavTile(
                    icon: Icons.grid_view_rounded,
                    title: 'Dashboard',
                    subtitle: 'Home insights and stats',
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 0);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.menu_book_rounded,
                    title: 'Library',
                    subtitle: 'Documents and generations',
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 1);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.upload_file_rounded,
                    title: 'Upload',
                    subtitle: 'Ingest and tag content',
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 2);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.auto_awesome_rounded,
                    title: 'Generation Lab',
                    subtitle: 'Create quizzes and exams',
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 3);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.schedule_rounded,
                    title: 'My Jobs',
                    subtitle: 'Track queued and completed generations',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openJobsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.notifications_active_rounded,
                    title: 'Notifications',
                    subtitle: 'Class and generation alerts',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openNotificationsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.class_rounded,
                    title: 'Classes',
                    subtitle: 'Schedule or join live classes',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openClassesPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.school_rounded,
                    title: 'Private Tutors',
                    subtitle: 'Browse and book on LocalPro KE',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openPrivateTutorsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.forum_rounded,
                    title: 'Topic Board',
                    subtitle: 'Suggest and upvote class topics',
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 4);
                    },
                  ),
                  if (widget.session.user.role.toLowerCase() == 'teacher')
                    _MenuNavTile(
                      icon: Icons.security_rounded,
                      title: 'Topic Moderation',
                      subtitle: 'Review abuse events and flagged topics',
                      badge: _flaggedTopicCount > 0
                          ? (_flaggedTopicCount > 99 ? '99+' : '$_flaggedTopicCount')
                          : null,
                      onTap: () {
                        Navigator.of(context).pop();
                        _openTopicModerationPage();
                      },
                    ),
                  if (widget.session.user.role.toLowerCase() == 'admin')
                    _MenuNavTile(
                      icon: Icons.admin_panel_settings_rounded,
                      title: 'Admin Dashboard',
                      subtitle: 'Platform wallet and user metrics',
                      onTap: () {
                        Navigator.of(context).pop();
                        _openAdminDashboardPage();
                      },
                    ),
                  const SizedBox(height: 10),
                  const _MenuSectionTitle('Profile Management'),
                  _MenuNavTile(
                    icon: Icons.person_outline_rounded,
                    title: 'My Profile',
                    subtitle: 'Update details and security',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openProfilePage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.workspace_premium_outlined,
                    title: 'Subscriptions',
                    subtitle: 'Manage billing and plans',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openSubscriptionsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.login_rounded,
                    title: 'Login Status',
                    subtitle: 'You are currently logged in',
                    onTap: () {
                      Navigator.of(context).pop();
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Session active.')),
                      );
                    },
                  ),
                  const SizedBox(height: 10),
                  const _MenuSectionTitle('Support'),
                  _MenuNavTile(
                    icon: Icons.info_outline_rounded,
                    title: 'About Exam OS',
                    subtitle: 'Mission, platform and trust',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openSupportPage(0);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.help_center_outlined,
                    title: 'Help',
                    subtitle: 'Setup guides and quick fixes',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openSupportPage(1);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.support_agent_rounded,
                    title: 'Contact',
                    subtitle: 'Email and phone support',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openSupportPage(2);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.gavel_rounded,
                    title: 'Terms & Conditions',
                    subtitle: 'Usage, billing and legal terms',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openTermsPage();
                    },
                  ),
                  const SizedBox(height: 14),
                  ListTile(
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                    leading: const Icon(
                      Icons.logout_rounded,
                      color: Colors.redAccent,
                    ),
                    title: const Text(
                      'Logout',
                      style: TextStyle(color: Colors.redAccent),
                    ),
                    subtitle: const Text('Sign out from this device'),
                    onTap: () {
                      Navigator.of(context).pop();
                      widget.onLogout();
                    },
                  ),
                ],
              ),
            ),
          ),
          extendBody: true,
          body: SafeArea(
            bottom: false,
            child: Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(14, 10, 14, 0),
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 8,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceDark.withValues(alpha: 0.72),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: Colors.white12),
                    ),
                    child: Row(
                      children: [
                        IconButton(
                          onPressed: () =>
                              _scaffoldKey.currentState?.openDrawer(),
                          icon: const Icon(Icons.menu_rounded),
                        ),
                        const SizedBox(width: 4),
                        Expanded(
                          child: Text(
                            _titleForIndex(_index),
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              fontWeight: FontWeight.w800,
                              fontSize: 18,
                              letterSpacing: 0.2,
                            ),
                          ),
                        ),
                        GestureDetector(
                          onTap: _openProfilePage,
                          child: CircleAvatar(
                            radius: 18,
                            backgroundColor: AppColors.primary.withValues(
                              alpha: 0.25,
                            ),
                            child: Text(
                              (widget.session.user.fullName.isNotEmpty
                                      ? widget.session.user.fullName[0]
                                      : widget.session.user.email[0])
                                  .toUpperCase(),
                              style: const TextStyle(
                                color: AppColors.primary,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Expanded(
                  child: AnimatedSwitcher(
                    duration: const Duration(milliseconds: 260),
                    switchInCurve: Curves.easeOutCubic,
                    switchOutCurve: Curves.easeInCubic,
                    child: KeyedSubtree(
                      key: ValueKey(_index),
                      child: Padding(
                        padding: const EdgeInsets.only(top: 10),
                        child: screens[_index],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          bottomNavigationBar: Container(
            padding: EdgeInsets.fromLTRB(
              16,
              10,
              16,
              10 + MediaQuery.of(context).padding.bottom,
            ),
            decoration: BoxDecoration(
              color: AppColors.surfaceDark.withValues(alpha: 0.85),
              borderRadius: const BorderRadius.vertical(
                top: Radius.circular(24),
              ),
              border: Border(
                top: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
              ),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Expanded(
                  child: _NavItem(
                    label: 'Dash',
                    icon: Icons.grid_view_rounded,
                    active: _index == 0,
                    onTap: () => setState(() => _index = 0),
                  ),
                ),
                Expanded(
                  child: _NavItem(
                    label: 'Library',
                    icon: Icons.menu_book_rounded,
                    active: _index == 1,
                    onTap: () => setState(() => _index = 1),
                  ),
                ),
                Expanded(
                  child: _NavItem(
                    label: 'Upload',
                    icon: Icons.upload_file_rounded,
                    active: _index == 2,
                    onTap: () => setState(() => _index = 2),
                  ),
                ),
                Expanded(
                  child: _NavItem(
                    label: 'Exam',
                    icon: Icons.auto_awesome_rounded,
                    active: _index == 3,
                    onTap: () => setState(() => _index = 3),
                  ),
                ),
                Expanded(
                  child: _NavItem(
                    label: 'Topics',
                    icon: Icons.forum_rounded,
                    active: _index == 4,
                    onTap: () => setState(() => _index = 4),
                  ),
                ),
              ],
            ),
          ),
        ),
        if (!_loadingCoachState && !_hasDocuments)
          _UploadCoachOverlay(onTap: () => setState(() => _index = 2)),
        if (_uploadCompleteNote != null)
          _GenerationCoachOverlay(message: _uploadCompleteNote!),
      ],
    );
  }
}

class _UploadCoachOverlay extends StatefulWidget {
  const _UploadCoachOverlay({required this.onTap});

  final VoidCallback onTap;

  @override
  State<_UploadCoachOverlay> createState() => _UploadCoachOverlayState();
}

class _UploadCoachOverlayState extends State<_UploadCoachOverlay>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final cardWidth = (screenWidth * 0.32).clamp(98.0, 122.0);
    final uploadCenterX = screenWidth * 0.625;
    final left = (uploadCenterX - (cardWidth / 2)).clamp(
      12.0,
      screenWidth - cardWidth - 12.0,
    );
    final bottom = 74.0 + MediaQuery.of(context).padding.bottom;

    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        final bob = (_controller.value - 0.5) * 5;
        return Positioned(
          left: left,
          bottom: bottom + bob,
          child: GestureDetector(onTap: widget.onTap, child: child),
        );
      },
      child: Material(
        color: Colors.transparent,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: cardWidth,
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 6),
              decoration: BoxDecoration(
                color: AppColors.surfaceDark.withValues(alpha: 0.96),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: AppColors.primary.withValues(alpha: 0.35),
                ),
                boxShadow: [
                  BoxShadow(
                    color: AppColors.primary.withValues(alpha: 0.2),
                    blurRadius: 10,
                    spreadRadius: 0.5,
                  ),
                ],
              ),
              child: const Text(
                'Upload first doc',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 8.7,
                  fontWeight: FontWeight.w600,
                  height: 1.0,
                ),
              ),
            ),
            CustomPaint(
              size: const Size(12, 6),
              painter: _ArrowPainter(strokeColor: AppColors.primary),
            ),
          ],
        ),
      ),
    );
  }
}

class _ArrowPainter extends CustomPainter {
  const _ArrowPainter({required this.strokeColor});

  final Color strokeColor;

  @override
  void paint(Canvas canvas, Size size) {
    final fill = Paint()..color = AppColors.surfaceDark.withValues(alpha: 0.96);
    final stroke = Paint()
      ..color = strokeColor.withValues(alpha: 0.35)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.2;
    final path = Path()
      ..moveTo(size.width / 2, size.height)
      ..lineTo(0, 0)
      ..lineTo(size.width, 0)
      ..close();
    canvas.drawPath(path, fill);
    canvas.drawPath(path, stroke);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _GenerationCoachOverlay extends StatefulWidget {
  const _GenerationCoachOverlay({required this.message});

  final String message;

  @override
  State<_GenerationCoachOverlay> createState() =>
      _GenerationCoachOverlayState();
}

class _GenerationCoachOverlayState extends State<_GenerationCoachOverlay>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1100),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final cardWidth = (screenWidth * 0.34).clamp(104.0, 132.0);
    final examCenterX = screenWidth * 0.875;
    final left = (examCenterX - (cardWidth / 2)).clamp(
      12.0,
      screenWidth - cardWidth - 12.0,
    );
    final bottom = 74.0 + MediaQuery.of(context).padding.bottom;

    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        final bob = (_controller.value - 0.5) * 5;
        return Positioned(left: left, bottom: bottom + bob, child: child!);
      },
      child: Material(
        color: Colors.transparent,
        child: IgnorePointer(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: cardWidth,
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 6),
                decoration: BoxDecoration(
                  color: AppColors.surfaceDark.withValues(alpha: 0.96),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: AppColors.accent.withValues(alpha: 0.35),
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: AppColors.accent.withValues(alpha: 0.18),
                      blurRadius: 10,
                      spreadRadius: 0.5,
                    ),
                  ],
                ),
                child: Text(
                  widget.message,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 8.4,
                    fontWeight: FontWeight.w600,
                    height: 1.1,
                  ),
                ),
              ),
              CustomPaint(
                size: const Size(12, 6),
                painter: _ArrowPainter(strokeColor: AppColors.accent),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NavItem extends StatelessWidget {
  const _NavItem({
    required this.label,
    required this.icon,
    required this.active,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool active;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = active ? AppColors.primary : AppColors.textMuted;
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            height: 44,
            width: 44,
            decoration: BoxDecoration(
              color: active
                  ? AppColors.primary.withValues(alpha: 0.18)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: active
                    ? AppColors.primary.withValues(alpha: 0.4)
                    : Colors.transparent,
              ),
            ),
            child: Icon(icon, color: color),
          ),
          const SizedBox(height: 6),
          FittedBox(
            fit: BoxFit.scaleDown,
            child: Text(
              label.toUpperCase(),
              style: TextStyle(
                color: color,
                fontSize: 9,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _MenuProfileCard extends StatelessWidget {
  const _MenuProfileCard({required this.user});

  final User user;

  @override
  Widget build(BuildContext context) {
    final initial =
        (user.fullName.isNotEmpty ? user.fullName[0] : user.email[0])
            .toUpperCase();
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(18),
        gradient: LinearGradient(
          colors: [
            AppColors.primary.withValues(alpha: 0.18),
            AppColors.accent.withValues(alpha: 0.12),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border.all(color: AppColors.glassBorder),
      ),
      child: Row(
        children: [
          CircleAvatar(
            radius: 24,
            backgroundColor: AppColors.surfaceDark,
            child: Text(
              initial,
              style: const TextStyle(
                color: AppColors.primary,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  user.fullName.isEmpty ? 'Learner' : user.fullName,
                  style: const TextStyle(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 2),
                Text(
                  user.email,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _MenuSectionTitle extends StatelessWidget {
  const _MenuSectionTitle(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(8, 2, 8, 8),
      child: Text(
        text.toUpperCase(),
        style: const TextStyle(
          fontSize: 11,
          letterSpacing: 1.5,
          color: AppColors.textMuted,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class _MenuNavTile extends StatelessWidget {
  const _MenuNavTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.badge,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final String? badge;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: ListTile(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        tileColor: Colors.white.withValues(alpha: 0.02),
        leading: Icon(icon, color: AppColors.primary),
        title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
        subtitle: Text(subtitle, style: const TextStyle(fontSize: 12)),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if ((badge ?? '').isNotEmpty)
              Container(
                margin: const EdgeInsets.only(right: 8),
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.redAccent.withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(999),
                  border: Border.all(color: Colors.redAccent.withValues(alpha: 0.5)),
                ),
                child: Text(
                  badge!,
                  style: const TextStyle(
                    color: Colors.redAccent,
                    fontSize: 11,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
            const Icon(
              Icons.chevron_right_rounded,
              color: AppColors.textMuted,
            ),
          ],
        ),
        onTap: onTap,
      ),
    );
  }
}
