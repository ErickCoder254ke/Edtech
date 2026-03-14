class AppConfig {
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://examos.cloudcrow.top',
  );
  static const String apiPrefix = '/api';
  static const String supportEmailFallback = 'examos254@gmail.com';
  static const String supportPhoneFallback = '0114090740';

  static String get apiRoot {
    final trimmed = apiBaseUrl.endsWith('/')
        ? apiBaseUrl.substring(0, apiBaseUrl.length - 1)
        : apiBaseUrl;
    return '$trimmed$apiPrefix';
  }
}

