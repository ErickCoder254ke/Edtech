import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import 'api_client.dart';

class PushNotificationService {
  PushNotificationService({required ApiClient apiClient}) : _apiClient = apiClient;

  final ApiClient _apiClient;
  final FlutterLocalNotificationsPlugin _localNotifications = FlutterLocalNotificationsPlugin();

  bool _initialized = false;
  bool _listenersAttached = false;
  String? _activeAccessToken;
  String? _registeredToken;

  Future<void> initializeForSession({
    required String accessToken,
  }) async {
    if (kIsWeb) return;
    final isSupportedMobile =
        defaultTargetPlatform == TargetPlatform.android ||
        defaultTargetPlatform == TargetPlatform.iOS;
    if (!isSupportedMobile) return;

    final ready = await _ensureInitialized();
    if (!ready) {
      debugPrint('push_init_failed firebase_not_initialized');
      return;
    }
    _activeAccessToken = accessToken;

    final messaging = FirebaseMessaging.instance;
    final permission = await messaging.requestPermission(alert: true, badge: true, sound: true);
    if (permission.authorizationStatus == AuthorizationStatus.denied) {
      debugPrint('push_permission_denied');
      return;
    }

    final token = await messaging.getToken();
    if (token != null && token.isNotEmpty && token != _registeredToken) {
      await _apiClient.registerPushToken(accessToken: accessToken, fcmToken: token);
      _registeredToken = token;
      debugPrint('push_token_registered ${token.substring(0, token.length > 12 ? 12 : token.length)}...');
    } else if (token == null || token.isEmpty) {
      debugPrint('push_token_missing');
    }

    if (!_listenersAttached) {
      _listenersAttached = true;
      FirebaseMessaging.instance.onTokenRefresh.listen((newToken) async {
        if (newToken.isEmpty || newToken == _registeredToken) return;
        final tokenForAuth = _activeAccessToken;
        if (tokenForAuth == null || tokenForAuth.isEmpty) return;
        try {
          await _apiClient.registerPushToken(accessToken: tokenForAuth, fcmToken: newToken);
          _registeredToken = newToken;
          debugPrint('push_token_refreshed');
        } catch (e) {
          debugPrint('push_token_refresh_register_failed $e');
        }
      });

      FirebaseMessaging.onMessage.listen((RemoteMessage message) async {
        final notification = message.notification;
        if (notification == null) return;
        await _localNotifications.show(
          message.hashCode,
          notification.title ?? 'Exam OS',
          notification.body ?? '',
          const NotificationDetails(
            android: AndroidNotificationDetails(
              'exam_os_alerts',
              'Exam OS Alerts',
              channelDescription: 'Generation and class alerts',
              importance: Importance.max,
              priority: Priority.high,
              playSound: true,
            ),
            iOS: DarwinNotificationDetails(presentAlert: true, presentBadge: true, presentSound: true),
          ),
        );
      });
    }
  }

  Future<bool> _ensureInitialized() async {
    if (_initialized) return true;
    try {
      if (Firebase.apps.isEmpty) {
        await Firebase.initializeApp();
      }
      const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
      const iosSettings = DarwinInitializationSettings();
      await _localNotifications.initialize(
        const InitializationSettings(android: androidSettings, iOS: iosSettings),
      );
      const channel = AndroidNotificationChannel(
        'exam_os_alerts',
        'Exam OS Alerts',
        description: 'Generation and class alerts',
        importance: Importance.high,
        playSound: true,
      );
      await _localNotifications
          .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>()
          ?.createNotificationChannel(channel);
      await _localNotifications
          .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>()
          ?.requestNotificationsPermission();
      await FirebaseMessaging.instance.setForegroundNotificationPresentationOptions(
        alert: true,
        badge: true,
        sound: true,
      );
      _initialized = true;
      return true;
    } catch (e) {
      debugPrint('push_ensure_init_error $e');
      return false;
    }
  }
}
