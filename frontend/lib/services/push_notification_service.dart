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
    if (!ready) return;
    _activeAccessToken = accessToken;

    final messaging = FirebaseMessaging.instance;
    await messaging.requestPermission(alert: true, badge: true, sound: true);

    final token = await messaging.getToken();
    if (token != null && token.isNotEmpty && token != _registeredToken) {
      await _apiClient.registerPushToken(accessToken: accessToken, fcmToken: token);
      _registeredToken = token;
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
        } catch (_) {}
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
      await Firebase.initializeApp();
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
      _initialized = true;
      return true;
    } catch (_) {
      return false;
    }
  }
}
