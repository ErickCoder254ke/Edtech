import 'dart:convert';
import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'config/app_config.dart';
import 'models/models.dart';
import 'screens/home_shell.dart';
import 'screens/login_screen.dart';
import 'screens/onboarding_screen.dart';
import 'screens/reset_password_screen.dart';
import 'services/api_client.dart';
import 'services/push_notification_service.dart';
import 'theme/app_theme.dart';
import 'widgets/exam_os_logo.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ExamOsApp());
}

class ExamOsApp extends StatefulWidget {
  const ExamOsApp({super.key});

  @override
  State<ExamOsApp> createState() => _ExamOsAppState();
}

class _ExamOsAppState extends State<ExamOsApp> {
  static const _sessionKey = 'edtech_session';
  static const _onboardingKey = 'first_run_completed';
  late final ApiClient _apiClient;
  late final PushNotificationService _pushNotificationService;
  Session? _session;
  bool _onboardingCompleted = false;
  bool _backendReachable = true;
  String? _backendError;
  bool _booting = true;
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();
  AppLinks? _appLinks;
  StreamSubscription<Uri>? _linkSub;
  String? _pendingResetToken;

  @override
  void initState() {
    super.initState();
    _apiClient = ApiClient(baseUrl: AppConfig.apiBaseUrl);
    _pushNotificationService = PushNotificationService(apiClient: _apiClient);
    _setupDeepLinks();
    _restoreSession();
  }

  @override
  void dispose() {
    _linkSub?.cancel();
    super.dispose();
  }

  void _handleLogin(Session session) {
    setState(() => _session = session);
    _saveSession(session);
    _registerPushToken(session);
  }

  void _handleSessionUpdate(Session session) {
    setState(() => _session = session);
    _saveSession(session);
    _registerPushToken(session);
  }

  Future<void> _handleLogout() async {
    final session = _session;
    if (session != null) {
      try {
        await _apiClient.logout(
          accessToken: session.accessToken,
          refreshToken: session.refreshToken,
        );
      } catch (_) {}
    }
    await _clearSession();
    setState(() => _session = null);
  }

  Future<void> _handlePasswordResetSuccess() async {
    await _clearSession();
    if (mounted) {
      setState(() => _session = null);
    }
  }

  Future<void> _restoreSession() async {
    try {
      final results = await Future.wait<dynamic>([
        SharedPreferences.getInstance(),
        _apiClient.healthCheck().timeout(const Duration(seconds: 6)),
      ], eagerError: false);
      final prefs = results[0] as SharedPreferences;
      final raw = prefs.getString(_sessionKey);
      _onboardingCompleted = prefs.getBool(_onboardingKey) ?? false;
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw) as Map<String, dynamic>;
        _session = Session.fromJson(decoded);
        _registerPushToken(_session!);
      }
      _backendReachable = true;
      _backendError = null;
    } on TimeoutException {
      _backendReachable = false;
      _backendError = 'Service is temporarily unavailable. Please try again.';
    } on ApiException {
      _backendReachable = false;
      _backendError = 'Service is temporarily unavailable. Please try again.';
    } catch (_) {}
    if (mounted) {
      setState(() => _booting = false);
    }
  }

  Future<void> _saveSession(Session session) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_sessionKey, jsonEncode(session.toJson()));
  }

  Future<void> _clearSession() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_sessionKey);
  }

  Future<void> _completeOnboarding() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_onboardingKey, true);
    if (mounted) {
      setState(() => _onboardingCompleted = true);
    }
  }

  Future<void> _retryBackendCheck() async {
    setState(() => _booting = true);
    await _restoreSession();
  }

  Future<void> _registerPushToken(Session session) async {
    try {
      await _pushNotificationService.initializeForSession(
        accessToken: session.accessToken,
      );
    } catch (e) {
      debugPrint('push_register_failed $e');
    }
  }

  Future<void> _setupDeepLinks() async {
    try {
      _appLinks = AppLinks();
      final initial = await _appLinks!.getInitialLink();
      _consumeResetLink(initial);
      _linkSub = _appLinks!.uriLinkStream.listen(
        (uri) => _consumeResetLink(uri),
        onError: (_) {},
      );
    } catch (_) {}
  }

  void _consumeResetLink(Uri? uri) {
    if (uri == null) return;
    if (uri.scheme.toLowerCase() != 'examos') return;
    if (uri.host.toLowerCase() != 'reset-password') return;
    final token = uri.queryParameters['token']?.trim();
    if (token == null || token.isEmpty) return;

    if (mounted) {
      setState(() => _pendingResetToken = token);
    } else {
      _pendingResetToken = token;
    }
    _openResetScreenIfReady();
  }

  void _openResetScreenIfReady() {
    if (_booting || !_backendReachable) return;
    final token = _pendingResetToken;
    if (token == null || token.isEmpty) return;
    final navigator = _navigatorKey.currentState;
    if (navigator == null) return;

    _pendingResetToken = null;
    navigator.push(
      MaterialPageRoute(
        builder: (_) => ResetPasswordScreen(
          apiClient: _apiClient,
          token: token,
          onPasswordResetSuccess: _handlePasswordResetSuccess,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: _navigatorKey,
      title: 'Exam OS',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      themeMode: ThemeMode.dark,
      home: _booting
          ? const _BootScreen()
          : !_backendReachable
          ? _BackendUnavailableScreen(
              message: _backendError ?? 'Backend unavailable.',
              onRetry: _retryBackendCheck,
            )
          : !_onboardingCompleted
          ? OnboardingScreen(onComplete: _completeOnboarding)
          : _session == null
          ? LoginScreen(
              apiClient: _apiClient,
              onLogin: _handleLogin,
            )
          : HomeShell(
              apiClient: _apiClient,
              session: _session!,
              onLogout: _handleLogout,
              onSessionUpdated: _handleSessionUpdate,
            ),
      builder: (context, child) {
        WidgetsBinding.instance.addPostFrameCallback((_) => _openResetScreenIfReady());
        return child ?? const SizedBox.shrink();
      },
    );
  }
}

class _BootScreen extends StatelessWidget {
  const _BootScreen();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: _BootAnimation(),
    );
  }
}

class _BootAnimation extends StatefulWidget {
  const _BootAnimation();

  @override
  State<_BootAnimation> createState() => _BootAnimationState();
}

class _BootAnimationState extends State<_BootAnimation>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1600),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF060A14), Color(0xFF0B1325)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: AnimatedBuilder(
        animation: _controller,
        builder: (context, child) {
          final scale = 0.96 + (_controller.value * 0.08);
          final opacity = 0.62 + (_controller.value * 0.38);
          return Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Transform.scale(
                  scale: scale,
                  child: Opacity(
                    opacity: opacity,
                    child: const ExamOsLogo(
                      size: 108,
                      showWordmark: true,
                      showTagline: true,
                    ),
                  ),
                ),
                const SizedBox(height: 22),
                SizedBox(
                  width: 140,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(999),
                    child: LinearProgressIndicator(
                      minHeight: 4,
                      value: null,
                      backgroundColor: Colors.white12,
                      valueColor: const AlwaysStoppedAnimation(Color(0xFF42E8E0)),
                    ),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _BackendUnavailableScreen extends StatelessWidget {
  const _BackendUnavailableScreen({
    required this.message,
    required this.onRetry,
  });

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.cloud_off_rounded, size: 48),
              const SizedBox(height: 14),
              const Text(
                'Cannot Reach Backend',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 10),
              Text(
                message,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 18),
              ElevatedButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
