import 'dart:async';

import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../theme/tokens.dart';
import 'dashboard_screen.dart';
import 'classes_screen.dart';
import 'admin_dashboard_screen.dart';
import 'admin_integrations_status_screen.dart';
import 'admin_teacher_verification_screen.dart';
import 'exam_configurator_screen.dart';
import 'jobs_screen.dart';
import 'library_screen.dart';
import 'notifications_screen.dart';
import 'notes_catalog_screen.dart';
import 'privacy_policy_screen.dart';
import 'profile_screen.dart';
import 'private_tutors_screen.dart';
import 'subscriptions_screen.dart';
import 'support_center_screen.dart';
import 'teacher_verification_screen.dart';
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
  String _teacherVerificationStatus = 'not_submitted';
  int _adminPrivateTutorsCount = 0;
  int _adminTeacherVerificationsPendingCount = 0;
  int _adminTeacherVerificationsRejectedCount = 0;
  int _adminIntegrationIssueCount = 0;
  int _unreadNotificationCount = 0;
  int _studentClassesToReviewCount = 0;
  int _teacherOpenAccessIssuesCount = 0;

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
    ).then((_) => _loadRoleMenuBadges());
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
    ).then((_) => _loadRoleMenuBadges());
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
    ).then((_) {
      if (widget.session.user.role.toLowerCase() == 'admin') {
        _loadAdminMenuBadges();
      }
    });
  }

  void _openNotesCatalogPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => NotesCatalogScreen(
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
    ).then((_) => _loadAdminMenuBadges());
  }

  void _openTeacherVerificationPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => TeacherVerificationScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    ).then((_) async {
      await _loadTeacherVerificationStatus();
      await _loadRoleMenuBadges();
    });
  }

  void _openAdminTeacherVerificationPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AdminTeacherVerificationScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    ).then((_) => _loadAdminMenuBadges());
  }

  void _openAdminIntegrationsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AdminIntegrationsStatusScreen(
          apiClient: widget.apiClient,
          session: widget.session,
          onSessionUpdated: widget.onSessionUpdated,
          onSessionInvalid: widget.onLogout,
        ),
      ),
    ).then((_) => _loadAdminMenuBadges());
  }

  @override
  void initState() {
    super.initState();
    _loadCoachState();
    _loadTopicModerationBadge();
    _loadTeacherVerificationStatus();
    _loadRoleMenuBadges();
    _loadAdminMenuBadges();
  }

  @override
  void didUpdateWidget(covariant HomeShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.session.accessToken != widget.session.accessToken) {
      _loadCoachState();
      _loadTopicModerationBadge();
      _loadTeacherVerificationStatus();
      _loadRoleMenuBadges();
      _loadAdminMenuBadges();
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

  Future<void> _loadTeacherVerificationStatus() async {
    if (widget.session.user.role.toLowerCase() != 'teacher') {
      if (mounted) setState(() => _teacherVerificationStatus = 'not_applicable');
      return;
    }
    try {
      final data = await _runWithAuthRetry(
        (token) => widget.apiClient.getMyTeacherVerification(accessToken: token),
      );
      if (!mounted) return;
      setState(() => _teacherVerificationStatus = data.status);
    } catch (_) {
      if (!mounted) return;
      setState(() => _teacherVerificationStatus = 'not_submitted');
    }
  }

  bool _isClassEnded(ClassSession session) {
    if (session.status.toLowerCase() == 'completed') return true;
    return !session.scheduledEndAt.isAfter(DateTime.now());
  }

  Future<void> _loadRoleMenuBadges() async {
    final role = widget.session.user.role.toLowerCase();
    try {
      final unread = await _runWithAuthRetry(
        (token) => widget.apiClient.listNotifications(
          accessToken: token,
          unreadOnly: true,
          limit: 120,
        ),
      );
      var studentToReview = 0;
      var teacherOpenIssues = 0;
      if (role == 'student' || role == 'teacher') {
        final classes = await _runWithAuthRetry(
          (token) => widget.apiClient.listClassSessions(
            accessToken: token,
            status: 'all',
            limit: 200,
          ),
        );
        if (role == 'student') {
          studentToReview = classes
              .where((c) => _isClassEnded(c) && c.joined && !c.studentReviewed)
              .length;
        } else if (role == 'teacher') {
          teacherOpenIssues = classes.fold<int>(
            0,
            (sum, c) => sum + c.openAccessIssueCount,
          );
        }
      }
      if (!mounted) return;
      setState(() {
        _unreadNotificationCount = unread.length;
        _studentClassesToReviewCount = studentToReview;
        _teacherOpenAccessIssuesCount = teacherOpenIssues;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _unreadNotificationCount = 0;
        _studentClassesToReviewCount = 0;
        _teacherOpenAccessIssuesCount = 0;
      });
    }
  }

  String? _badgeForCount(int count, {int cap = 99}) {
    if (count <= 0) return null;
    if (count > cap) return '$cap+';
    return '$count';
  }

  int _countAdminIntegrationIssues(Map<String, dynamic> status) {
    final localpro = (status['localpro'] as Map<String, dynamic>?) ?? const {};
    final firebase = (status['firebase'] as Map<String, dynamic>?) ?? const {};
    final brevo = (status['brevo'] as Map<String, dynamic>?) ?? const {};
    final queue = (status['queue'] as Map<String, dynamic>?) ?? const {};
    final payments = (status['payments'] as Map<String, dynamic>?) ?? const {};

    var issues = 0;
    if (localpro['configured'] != true) issues += 1;
    if ((localpro['last_fetch_error']?.toString().trim().isNotEmpty ?? false)) {
      issues += 1;
    }
    if (firebase['enabled'] == true && firebase['ready'] != true) issues += 1;
    if (brevo['has_brevo_api_key'] != true) issues += 1;
    if (queue['redis_ping_ok'] != true) issues += 1;

    final queuedStale = (queue['queued_stale_count'] as num?)?.toInt() ?? 0;
    if (queuedStale > 0) issues += 1;
    final callbackFailed = (payments['callbacks_failed_24h'] as num?)?.toInt() ?? 0;
    final callbackThreshold =
        (payments['callback_failure_alert_threshold_24h'] as num?)?.toInt() ??
        0;
    if (callbackThreshold > 0 && callbackFailed >= callbackThreshold) issues += 1;
    return issues;
  }

  Future<void> _loadAdminMenuBadges() async {
    if (widget.session.user.role.toLowerCase() != 'admin') {
      if (!mounted) return;
      setState(() {
        _adminPrivateTutorsCount = 0;
        _adminTeacherVerificationsPendingCount = 0;
        _adminTeacherVerificationsRejectedCount = 0;
        _adminIntegrationIssueCount = 0;
      });
      return;
    }
    try {
      final results = await Future.wait<dynamic>([
        _runWithAuthRetry(
          (token) => widget.apiClient.listPrivateTutors(
            accessToken: token,
            limit: 60,
          ),
        ),
        _runWithAuthRetry(
          (token) => widget.apiClient.listTeacherVerifications(
            accessToken: token,
            status: 'pending',
            limit: 200,
          ),
        ),
        _runWithAuthRetry(
          (token) => widget.apiClient.listTeacherVerifications(
            accessToken: token,
            status: 'rejected',
            limit: 200,
          ),
        ),
        _runWithAuthRetry(
          (token) => widget.apiClient.getAdminIntegrationStatus(
            accessToken: token,
          ),
        ),
      ]);
      if (!mounted) return;
      final tutors = results[0] as List<PrivateTutorProfile>;
      final pending = results[1] as List<TeacherVerification>;
      final rejected = results[2] as List<TeacherVerification>;
      final integrationStatus = results[3] as Map<String, dynamic>;
      setState(() {
        _adminPrivateTutorsCount = tutors.length;
        _adminTeacherVerificationsPendingCount = pending.length;
        _adminTeacherVerificationsRejectedCount = rejected.length;
        _adminIntegrationIssueCount = _countAdminIntegrationIssues(
          integrationStatus,
        );
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _adminPrivateTutorsCount = 0;
        _adminTeacherVerificationsPendingCount = 0;
        _adminTeacherVerificationsRejectedCount = 0;
        _adminIntegrationIssueCount = 0;
      });
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

  void _openPrivacyPage() {
    Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => const PrivacyPolicyScreen()));
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
        const _ShellBackground(),
        Scaffold(
          backgroundColor: Colors.transparent,
          key: _scaffoldKey,
          drawer: Drawer(
            width: 338,
            backgroundColor: Colors.transparent,
            elevation: 0,
            shape: const RoundedRectangleBorder(
              borderRadius: BorderRadius.horizontal(right: Radius.circular(28)),
            ),
            child: Container(
              decoration: BoxDecoration(
                borderRadius: const BorderRadius.horizontal(
                  right: Radius.circular(28),
                ),
                gradient: LinearGradient(
                  colors: [
                    AppColors.surfaceDark.withValues(alpha: 0.96),
                    AppColors.backgroundDark.withValues(alpha: 0.96),
                    AppColors.backgroundDeep.withValues(alpha: 0.96),
                  ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                border: Border.all(color: AppColors.glassBorder),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.35),
                    blurRadius: 22,
                    offset: const Offset(2, 0),
                  ),
                ],
              ),
              child: SafeArea(
                child: ListView(
                  padding: const EdgeInsets.fromLTRB(14, 16, 14, 22),
                  children: [
                    _MenuProfileCard(
                      user: widget.session.user,
                      teacherVerificationStatus: _teacherVerificationStatus,
                    ),
                    const SizedBox(height: 12),
                    _MenuQuickActions(
                      onDashboard: () {
                        Navigator.of(context).pop();
                        setState(() => _index = 0);
                      },
                      onGeneration: () {
                        Navigator.of(context).pop();
                        setState(() => _index = 3);
                      },
                      onJobs: () {
                        Navigator.of(context).pop();
                        _openJobsPage();
                      },
                      onClasses: () {
                        Navigator.of(context).pop();
                        _openClassesPage();
                      },
                    ),
                    const SizedBox(height: 14),
                  const _MenuSectionTitle('Shortcuts'),
                  _MenuNavTile(
                    icon: Icons.grid_view_rounded,
                    title: 'Dashboard',
                    subtitle: 'Home insights and stats',
                    active: _index == 0,
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 0);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.menu_book_rounded,
                    title: 'Library',
                    subtitle: 'Documents and generations',
                    active: _index == 1,
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 1);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.upload_file_rounded,
                    title: 'Upload',
                    subtitle: 'Ingest and tag content',
                    active: _index == 2,
                    onTap: () {
                      Navigator.of(context).pop();
                      setState(() => _index = 2);
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.auto_awesome_rounded,
                    title: 'Generation Lab',
                    subtitle: 'Create quizzes and exams',
                    active: _index == 3,
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
                    badge: _badgeForCount(_unreadNotificationCount),
                    onTap: () {
                      Navigator.of(context).pop();
                      _openNotificationsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.class_rounded,
                    title: 'Classes',
                    subtitle: 'Schedule or join live classes',
                    badge: widget.session.user.role.toLowerCase() == 'student'
                        ? _badgeForCount(_studentClassesToReviewCount)
                        : (widget.session.user.role.toLowerCase() == 'teacher'
                              ? _badgeForCount(_teacherOpenAccessIssuesCount)
                              : null),
                    onTap: () {
                      Navigator.of(context).pop();
                      _openClassesPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.school_rounded,
                    title: 'Private Tutors',
                    subtitle: 'Browse and book on LocalPro KE',
                    badge: widget.session.user.role.toLowerCase() == 'admin'
                        ? _badgeForCount(_adminPrivateTutorsCount)
                        : null,
                    onTap: () {
                      Navigator.of(context).pop();
                      _openPrivateTutorsPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.menu_book_outlined,
                    title: 'CBC / Senior School Notes',
                    subtitle: 'Pick form or grade and generate from uploaded notes',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openNotesCatalogPage();
                    },
                  ),
                  _MenuNavTile(
                    icon: Icons.forum_rounded,
                    title: 'Topic Board',
                    subtitle: 'Suggest and upvote class topics',
                    active: _index == 4,
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
                  if (widget.session.user.role.toLowerCase() == 'teacher')
                    _MenuNavTile(
                      icon: Icons.verified_user_rounded,
                      title: 'Teacher Verification',
                      subtitle: 'Submit TSC and ID for approval',
                      badge: _teacherVerificationStatus == 'pending'
                          ? 'P'
                          : (_teacherVerificationStatus == 'rejected' ? '!' : null),
                      onTap: () {
                        Navigator.of(context).pop();
                        _openTeacherVerificationPage();
                      },
                    ),
                  if (widget.session.user.role.toLowerCase() == 'admin')
                    _MenuNavTile(
                      icon: Icons.admin_panel_settings_rounded,
                      title: 'Admin Dashboard',
                      subtitle: 'Platform wallet and user metrics',
                      badge: _badgeForCount(_adminIntegrationIssueCount),
                      onTap: () {
                        Navigator.of(context).pop();
                        _openAdminDashboardPage();
                      },
                    ),
                  if (widget.session.user.role.toLowerCase() == 'admin')
                    _MenuNavTile(
                      icon: Icons.fact_check_rounded,
                      title: 'Teacher Verifications',
                      subtitle: 'Approve or reject teacher documents',
                      badge: _adminTeacherVerificationsPendingCount > 0 ||
                              _adminTeacherVerificationsRejectedCount > 0
                          ? 'P$_adminTeacherVerificationsPendingCount'
                              '/R$_adminTeacherVerificationsRejectedCount'
                          : null,
                      onTap: () {
                        Navigator.of(context).pop();
                        _openAdminTeacherVerificationPage();
                      },
                    ),
                  if (widget.session.user.role.toLowerCase() == 'admin')
                    _MenuNavTile(
                      icon: Icons.hub_rounded,
                      title: 'Integrations',
                      subtitle: 'LocalPro, Firebase, Brevo and queue health',
                      badge: _badgeForCount(_adminIntegrationIssueCount),
                      onTap: () {
                        Navigator.of(context).pop();
                        _openAdminIntegrationsPage();
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
                  _MenuNavTile(
                    icon: Icons.privacy_tip_rounded,
                    title: 'Privacy Policy',
                    subtitle: 'Data handling and retention policy',
                    onTap: () {
                      Navigator.of(context).pop();
                      _openPrivacyPage();
                    },
                  ),
                  const SizedBox(height: 14),
                  FilledButton.icon(
                    style: FilledButton.styleFrom(
                      minimumSize: const Size(double.infinity, 52),
                      backgroundColor: Colors.redAccent.withValues(alpha: 0.15),
                      foregroundColor: Colors.redAccent,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14),
                        side: BorderSide(
                          color: Colors.redAccent.withValues(alpha: 0.45),
                        ),
                      ),
                    ),
                    onPressed: () {
                      Navigator.of(context).pop();
                      widget.onLogout();
                    },
                    icon: const Icon(Icons.logout_rounded),
                    label: const Text(
                      'Logout',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                  ),
                ],
              ),
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
              AppTokens.spaceLg,
              AppTokens.spaceSm + 2,
              AppTokens.spaceLg,
              AppTokens.spaceSm + MediaQuery.of(context).padding.bottom,
            ),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  AppColors.surfaceDark.withValues(alpha: 0.86),
                  AppColors.backgroundDeep.withValues(alpha: 0.94),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.vertical(
                top: Radius.circular(AppTokens.radiusLg + 6),
              ),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
              boxShadow: [
                BoxShadow(
                  color: AppColors.primary.withValues(alpha: 0.14),
                  blurRadius: AppTokens.shadowBlur,
                  offset: const Offset(0, -2),
                ),
              ],
            ),
            child: Stack(
              alignment: Alignment.center,
              clipBehavior: Clip.none,
              children: [
                Row(
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
                    const SizedBox(width: AppTokens.spaceXl + 32),
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
                        label: 'Topics',
                        icon: Icons.forum_rounded,
                        active: _index == 4,
                        onTap: () => setState(() => _index = 4),
                      ),
                    ),
                  ],
                ),
                Positioned(
                  top: -AppTokens.spaceSm,
                  child: GestureDetector(
                    onTap: () => setState(() => _index = 3),
                    child: Container(
                      height: 64,
                      width: 64,
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [AppColors.primary, AppColors.accent],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: AppColors.primary.withValues(alpha: 0.35),
                            blurRadius: AppTokens.shadowBlur,
                            offset: const Offset(0, 8),
                          ),
                        ],
                      ),
                      child: const Icon(
                        Icons.auto_awesome_rounded,
                        color: Colors.white,
                        size: 28,
                      ),
                    ),
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

class _ShellBackground extends StatelessWidget {
  const _ShellBackground();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        children: const [
          Positioned(
            top: -80,
            left: -60,
            child: _BackdropBlob(color: AppColors.primary, size: 260),
          ),
          Positioned(
            bottom: -60,
            right: -60,
            child: _BackdropBlob(color: AppColors.accent, size: 240),
          ),
          Positioned(
            bottom: 120,
            left: 80,
            child: _BackdropBlob(color: AppColors.electric, size: 180),
          ),
        ],
      ),
    );
  }
}

class _BackdropBlob extends StatelessWidget {
  const _BackdropBlob({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: size,
      width: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color.withValues(alpha: 0.06),
        boxShadow: [
          BoxShadow(
            color: color.withValues(alpha: 0.16),
            blurRadius: size / 2,
            spreadRadius: size / 4,
          ),
        ],
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
    final color = active ? Colors.white : AppColors.textMuted;
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          AnimatedContainer(
            duration: AppTokens.motionFast,
            height: 48,
            width: 48,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: active
                    ? [
                        AppColors.primary.withValues(alpha: 0.9),
                        AppColors.electric.withValues(alpha: 0.78),
                      ]
                    : [
                        Colors.white.withValues(alpha: 0.05),
                        Colors.white.withValues(alpha: 0.03),
                      ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: active
                    ? AppColors.primary.withValues(alpha: 0.55)
                    : Colors.white.withValues(alpha: 0.08),
              ),
              boxShadow: active
                  ? [
                      BoxShadow(
                        color: AppColors.primary.withValues(alpha: 0.25),
                        blurRadius: 14,
                        spreadRadius: 1,
                        offset: const Offset(0, 6),
                      ),
                    ]
                  : [],
            ),
            child: Icon(icon, color: color),
          ),
          const SizedBox(height: 6),
          FittedBox(
            fit: BoxFit.scaleDown,
            child: Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 10,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _MenuProfileCard extends StatelessWidget {
  const _MenuProfileCard({
    required this.user,
    required this.teacherVerificationStatus,
  });

  final User user;
  final String teacherVerificationStatus;

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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  user.role.toUpperCase(),
                  style: const TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
              if (user.role.toLowerCase() == 'teacher')
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: teacherVerificationStatus == 'approved'
                        ? Colors.green.withValues(alpha: 0.22)
                        : teacherVerificationStatus == 'pending'
                            ? Colors.orange.withValues(alpha: 0.22)
                            : Colors.red.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    teacherVerificationStatus.toUpperCase(),
                    style: const TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.6,
                    ),
                  ),
                ),
              const Icon(
                Icons.shield_outlined,
                size: 16,
                color: AppColors.textMuted,
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
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
      padding: const EdgeInsets.fromLTRB(8, 4, 8, 10),
      child: Row(
        children: [
          Text(
            text.toUpperCase(),
            style: const TextStyle(
              fontSize: 11,
              letterSpacing: 1.5,
              color: AppColors.textMuted,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Container(
              height: 1,
              color: Colors.white.withValues(alpha: 0.08),
            ),
          ),
        ],
      ),
    );
  }
}

class _MenuQuickActions extends StatelessWidget {
  const _MenuQuickActions({
    required this.onDashboard,
    required this.onGeneration,
    required this.onJobs,
    required this.onClasses,
  });

  final VoidCallback onDashboard;
  final VoidCallback onGeneration;
  final VoidCallback onJobs;
  final VoidCallback onClasses;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(16),
        color: Colors.white.withValues(alpha: 0.03),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Row(
        children: [
          Expanded(
            child: _MenuShortcutChip(
              label: 'Dash',
              icon: Icons.grid_view_rounded,
              onTap: onDashboard,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: _MenuShortcutChip(
              label: 'Gen',
              icon: Icons.auto_awesome_rounded,
              onTap: onGeneration,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: _MenuShortcutChip(
              label: 'Jobs',
              icon: Icons.schedule_rounded,
              onTap: onJobs,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: _MenuShortcutChip(
              label: 'Class',
              icon: Icons.class_rounded,
              onTap: onClasses,
            ),
          ),
        ],
      ),
    );
  }
}

class _MenuShortcutChip extends StatelessWidget {
  const _MenuShortcutChip({
    required this.label,
    required this.icon,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(12),
      onTap: onTap,
      child: Ink(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          color: Colors.white.withValues(alpha: 0.05),
          border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 18, color: AppColors.accent),
            const SizedBox(height: 4),
            Text(
              label,
              style: const TextStyle(
                fontSize: 10,
                letterSpacing: 0.3,
                fontWeight: FontWeight.w700,
                color: AppColors.textMuted,
              ),
            ),
          ],
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
    this.active = false,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final String? badge;
  final bool active;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onTap,
        child: Ink(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            gradient: active
                ? LinearGradient(
                    colors: [
                      AppColors.primary.withValues(alpha: 0.2),
                      AppColors.accent.withValues(alpha: 0.12),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  )
                : null,
            color: active ? null : Colors.white.withValues(alpha: 0.03),
            border: Border.all(
              color: active
                  ? AppColors.primary.withValues(alpha: 0.45)
                  : Colors.white.withValues(alpha: 0.08),
            ),
          ),
          child: Row(
            children: [
              Container(
                height: 36,
                width: 36,
                decoration: BoxDecoration(
                  color: active
                      ? AppColors.primary.withValues(alpha: 0.26)
                      : Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(11),
                ),
                child: Icon(
                  icon,
                  size: 19,
                  color: active ? AppColors.primary : Colors.white70,
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontWeight: FontWeight.w700,
                        color: active ? Colors.white : null,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(subtitle, style: const TextStyle(fontSize: 12)),
                  ],
                ),
              ),
              if ((badge ?? '').isNotEmpty)
                Container(
                  margin: const EdgeInsets.only(right: 8),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.redAccent.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(999),
                    border: Border.all(
                      color: Colors.redAccent.withValues(alpha: 0.5),
                    ),
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
              Icon(
                Icons.chevron_right_rounded,
                color: active ? Colors.white70 : AppColors.textMuted,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

