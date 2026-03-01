import 'dart:async';
import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/app_config.dart';
import '../models/models.dart';

class ApiException implements Exception {
  ApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => 'ApiException($statusCode): $message';
}

class ApiClient {
  ApiClient({required this.baseUrl});

  final String baseUrl;
  static const Duration _requestTimeout = Duration(seconds: 45);
  static const Duration _healthTimeout = Duration(seconds: 6);
  static const Duration _generationTimeout = Duration(minutes: 2);
  static const Duration _uploadTimeout = Duration(minutes: 8);

  Uri _uri(String path) {
    final trimmedBase = baseUrl.endsWith('/')
        ? baseUrl.substring(0, baseUrl.length - 1)
        : baseUrl;
    final normalizedPath = path.startsWith('/') ? path : '/$path';
    return Uri.parse('$trimmedBase${AppConfig.apiPrefix}$normalizedPath');
  }

  Future<Map<String, dynamic>> healthCheck() async {
    final response = await _sendRequest(
      () => http
          .get(_uri('/health'), headers: _jsonHeaders())
          .timeout(_healthTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<TokenResponse> login({
    required String email,
    required String password,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/login'),
            headers: _jsonHeaders(),
            body: jsonEncode({'email': email, 'password': password}),
          )
          .timeout(_requestTimeout),
    );
    return _parseTokenResponse(response);
  }

  Future<SignupChallenge> register({
    required String email,
    required String password,
    required String fullName,
    String role = 'student',
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/register'),
            headers: _jsonHeaders(),
            body: jsonEncode({
              'email': email,
              'password': password,
              'full_name': fullName,
              'role': role,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return SignupChallenge.fromJson(data as Map<String, dynamic>);
  }

  Future<TokenResponse> verifySignupOtp({
    required String signupId,
    required String otp,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/register/verify'),
            headers: _jsonHeaders(),
            body: jsonEncode({'signup_id': signupId, 'otp': otp}),
          )
          .timeout(_requestTimeout),
    );
    return _parseTokenResponse(response);
  }

  Future<void> resendSignupOtp({required String signupId}) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/auth/register/resend'),
            headers: _jsonHeaders(),
            body: jsonEncode({'signup_id': signupId}),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> requestPasswordReset({required String email}) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/auth/password-reset/request'),
            headers: _jsonHeaders(),
            body: jsonEncode({'email': email}),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> confirmPasswordReset({
    required String token,
    required String newPassword,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/auth/password-reset/confirm'),
            headers: _jsonHeaders(),
            body: jsonEncode({'token': token, 'new_password': newPassword}),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<TokenResponse> refreshTokens({required String refreshToken}) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/refresh'),
            headers: _jsonHeaders(),
            body: jsonEncode({'refresh_token': refreshToken}),
          )
          .timeout(_requestTimeout),
    );
    return _parseTokenResponse(response);
  }

  Future<User> getProfile(String accessToken) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/auth/me'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return User.fromJson(data);
  }

  Future<User> updateProfile({
    required String accessToken,
    String? fullName,
    String? email,
  }) async {
    final payload = <String, dynamic>{};
    if (fullName != null) payload['full_name'] = fullName;
    if (email != null) payload['email'] = email;

    final response = await _sendRequest(
      () => http
          .put(
            _uri('/auth/me'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode(payload),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return User.fromJson(data);
  }

  Future<void> changePassword({
    required String accessToken,
    required String currentPassword,
    required String newPassword,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/auth/change-password'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'current_password': currentPassword,
              'new_password': newPassword,
            }),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<String> deleteAccount({
    required String accessToken,
    required String password,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/delete-account'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'password': password}),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    if (data is Map<String, dynamic>) {
      return data['message']?.toString() ?? 'Account deleted successfully.';
    }
    return 'Account deleted successfully.';
  }

  Future<List<DocumentMetadata>> listDocuments(
    String accessToken, {
    int limit = 50,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/documents?limit=$limit'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((doc) => DocumentMetadata.fromJson(doc as Map<String, dynamic>))
        .toList();
  }

  Future<CbcNoteCategories> listCbcNoteCategories({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/notes/categories'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return CbcNoteCategories.fromJson(data as Map<String, dynamic>);
  }

  Future<List<CbcNote>> listCbcNotes({
    required String accessToken,
    int? grade,
    String? subject,
    String? q,
    int limit = 100,
  }) async {
    final params = <String, String>{
      'limit': '$limit',
      if (grade != null) 'grade': '$grade',
      if ((subject ?? '').trim().isNotEmpty) 'subject': subject!.trim(),
      if ((q ?? '').trim().isNotEmpty) 'q': q!.trim(),
    };
    final uri = _uri('/v1/notes').replace(queryParameters: params);
    final response = await _sendRequest(
      () => http
          .get(uri, headers: _jsonHeaders(accessToken: accessToken))
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => CbcNote.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<Map<String, dynamic>> importCbcNoteToLibrary({
    required String accessToken,
    required String noteId,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/notes/$noteId/import'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(const Duration(minutes: 3)),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : <String, dynamic>{};
  }

  Future<List<GenerationResponse>> listGenerations(
    String accessToken, {
    int limit = 50,
    bool compact = false,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/generations?limit=$limit&compact=$compact'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((gen) => GenerationResponse.fromJson(gen as Map<String, dynamic>))
        .toList();
  }

  Future<GenerationResponse> getGeneration({
    required String accessToken,
    required String generationId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/generations/$generationId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return GenerationResponse.fromJson(data);
  }

  Future<Map<String, dynamic>> getDashboardOverview({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/dashboard/overview'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, String>> getSupportContact() async {
    final response = await _sendRequest(
      () => http
          .get(_uri('/config'), headers: _jsonHeaders())
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    if (data is! Map<String, dynamic>) {
      return {};
    }
    return {
      'email': data['support_contact_email']?.toString() ?? '',
      'phone': data['support_contact_phone']?.toString() ?? '',
    };
  }

  Future<Map<String, dynamic>> getRuntimeConfig() async {
    final response = await _sendRequest(
      () => http
          .get(_uri('/config'), headers: _jsonHeaders())
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : <String, dynamic>{};
  }

  Future<DocumentMetadata> uploadDocument({
    required String accessToken,
    required PlatformFile file,
  }) async {
    final request = http.MultipartRequest('POST', _uri('/documents/upload'))
      ..headers.addAll(_authHeaders(accessToken));

    if (file.bytes != null) {
      request.files.add(
        http.MultipartFile.fromBytes('file', file.bytes!, filename: file.name),
      );
    } else if (!kIsWeb && file.path != null) {
      request.files.add(await http.MultipartFile.fromPath('file', file.path!));
    } else {
      throw ApiException('Unable to read file contents for upload.');
    }
    final streamed = await _sendStreamedRequest(
      () => request.send().timeout(_uploadTimeout),
    );
    final response = await _sendRequest(
      () => http.Response.fromStream(streamed).timeout(_uploadTimeout),
      timeoutMessage:
          'Upload processing is taking longer than expected. Please try a smaller file or retry.',
      networkMessage: 'Network error while finalizing upload. Please retry.',
    );
    final data = _parseJson(response);
    return DocumentMetadata.fromJson(data);
  }

  Future<GenerationJobResponse> generate({
    required String accessToken,
    required GenerationRequest request,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/generate'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode(request.toJson()),
          )
          .timeout(_generationTimeout),
    );
    final data = _parseJson(response);
    if (data is! Map<String, dynamic>) {
      throw ApiException('Server returned an invalid generation response.');
    }
    final jobId = (data['job_id'] as String?)?.trim() ?? '';
    if (jobId.isEmpty) {
      final looksLikeLegacyGeneration =
          data.containsKey('id') &&
          data.containsKey('generation_type') &&
          data.containsKey('content');
      if (looksLikeLegacyGeneration) {
        throw ApiException(
          'Backend is running legacy /generate response format. Deploy latest backend with async jobs support.',
        );
      }
      throw ApiException('Server did not return a valid job_id for generation.');
    }
    return GenerationJobResponse.fromJson(data);
  }

  Future<JobStatusResponse> getJobStatus({
    required String accessToken,
    required String jobId,
  }) async {
    final safeJobId = jobId.trim();
    if (safeJobId.isEmpty) {
      throw ApiException('Job ID is missing. Generation cannot be tracked.');
    }
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/jobs/$safeJobId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return JobStatusResponse.fromJson(data as Map<String, dynamic>);
  }

  Future<List<JobStatusResponse>> listJobs({
    required String accessToken,
    int limit = 50,
    String? status,
  }) async {
    final statusQuery = status == null || status.trim().isEmpty
        ? ''
        : '&status=${Uri.encodeQueryComponent(status.trim())}';
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/jobs?limit=$limit$statusQuery'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => JobStatusResponse.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<ClassSession> createClassSession({
    required String accessToken,
    required String title,
    String? description,
    required String meetingLink,
    required DateTime scheduledStartAt,
    required DateTime scheduledEndAt,
    required int feeKes,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/classes'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'title': title,
              'description': description,
              'meeting_link': meetingLink,
              'scheduled_start_at': scheduledStartAt.toUtc().toIso8601String(),
              'scheduled_end_at': scheduledEndAt.toUtc().toIso8601String(),
              'fee_kes': feeKes,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return ClassSession.fromJson(data as Map<String, dynamic>);
  }

  Future<List<ClassSession>> listClassSessions({
    required String accessToken,
    String status = 'upcoming',
    int limit = 50,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri(
              '/v1/classes?status=${Uri.encodeQueryComponent(status)}&limit=$limit',
            ),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => ClassSession.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<ClassSession> getClassSession({
    required String accessToken,
    required String classId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/classes/$classId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return ClassSession.fromJson(data as Map<String, dynamic>);
  }

  Future<ClassSession> completeClassSession({
    required String accessToken,
    required String classId,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/classes/$classId/complete'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return ClassSession.fromJson(data as Map<String, dynamic>);
  }

  Future<Map<String, dynamic>> joinClassSession({
    required String accessToken,
    required String classId,
    String? phoneNumber,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/classes/$classId/join'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'phone_number': phoneNumber}),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> classPaymentStatus({
    required String accessToken,
    required String classId,
    required String checkoutRequestId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/classes/$classId/payment/$checkoutRequestId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> classEarnings({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/classes/earnings/me'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> requestClassWithdrawal({
    required String accessToken,
    required int amountKes,
    String? phoneNumber,
    String? note,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/classes/withdrawals'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'amount_kes': amountKes,
              'phone_number': phoneNumber,
              'note': note,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<ClassReview> createClassReview({
    required String accessToken,
    required String classId,
    required int rating,
    String? comment,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/classes/$classId/reviews'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'rating': rating, 'comment': comment}),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return ClassReview.fromJson(data as Map<String, dynamic>);
  }

  Future<List<ClassReview>> listClassReviews({
    required String accessToken,
    required String classId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/classes/$classId/reviews'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => ClassReview.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<List<NotificationItem>> listNotifications({
    required String accessToken,
    int limit = 60,
    bool unreadOnly = false,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/notifications?limit=$limit&unread_only=$unreadOnly'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => NotificationItem.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<void> registerPushToken({
    required String accessToken,
    required String fcmToken,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/v1/notifications/register-token'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'fcm_token': fcmToken}),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<Map<String, dynamic>> getPushHealth({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/notifications/push-health'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : <String, dynamic>{};
  }

  Future<void> sendTestPush({
    required String accessToken,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/v1/notifications/test-push'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<TeacherVerification> getMyTeacherVerification({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/teacher-verification/me'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return TeacherVerification.fromJson(data as Map<String, dynamic>);
  }

  Future<List<TeacherVerificationAuditEntry>> getMyTeacherVerificationHistory({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/teacher-verification/history'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map(
          (item) => TeacherVerificationAuditEntry.fromJson(
            item as Map<String, dynamic>,
          ),
        )
        .toList();
  }

  Future<TeacherVerification> submitTeacherVerification({
    required String accessToken,
    required String tscNumber,
    required PlatformFile idDocument,
    required PlatformFile tscCertificate,
  }) async {
    return submitTeacherVerificationFlexible(
      accessToken: accessToken,
      tscNumber: tscNumber,
      idDocument: idDocument,
      tscCertificate: tscCertificate,
    );
  }

  Future<TeacherVerification> submitTeacherVerificationFlexible({
    required String accessToken,
    required String tscNumber,
    PlatformFile? idDocument,
    PlatformFile? tscCertificate,
  }) async {
    final request = http.MultipartRequest(
      'POST',
      _uri('/v1/teacher-verification/submit'),
    )..headers.addAll(_authHeaders(accessToken));
    request.fields['tsc_number'] = tscNumber.trim();

    if (idDocument != null) {
      if (idDocument.bytes != null) {
        request.files.add(
          http.MultipartFile.fromBytes(
            'id_document',
            idDocument.bytes!,
            filename: idDocument.name,
          ),
        );
      } else if (!kIsWeb && idDocument.path != null) {
        request.files.add(
          await http.MultipartFile.fromPath('id_document', idDocument.path!),
        );
      } else {
        throw ApiException('Unable to read ID document file.');
      }
    }

    if (tscCertificate != null) {
      if (tscCertificate.bytes != null) {
        request.files.add(
          http.MultipartFile.fromBytes(
            'tsc_certificate',
            tscCertificate.bytes!,
            filename: tscCertificate.name,
          ),
        );
      } else if (!kIsWeb && tscCertificate.path != null) {
        request.files.add(
          await http.MultipartFile.fromPath(
            'tsc_certificate',
            tscCertificate.path!,
          ),
        );
      } else {
        throw ApiException('Unable to read TSC certificate file.');
      }
    }

    final streamed = await _sendStreamedRequest(
      () => request.send().timeout(_uploadTimeout),
    );
    final response = await _sendRequest(
      () => http.Response.fromStream(streamed).timeout(_uploadTimeout),
    );
    final data = _parseJson(response);
    return TeacherVerification.fromJson(data as Map<String, dynamic>);
  }

  Future<List<TeacherVerification>> listTeacherVerifications({
    required String accessToken,
    String status = 'pending',
    int limit = 80,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri(
              '/v1/admin/teacher-verifications?status=${Uri.encodeQueryComponent(status)}&limit=$limit',
            ),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => TeacherVerification.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<TeacherVerification> reviewTeacherVerification({
    required String accessToken,
    required String teacherId,
    required String action,
    String? comment,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/admin/teacher-verifications/$teacherId/review'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'action': action, 'comment': comment}),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return TeacherVerification.fromJson(data as Map<String, dynamic>);
  }

  Future<List<TeacherVerificationAuditEntry>> getTeacherVerificationHistory({
    required String accessToken,
    required String teacherId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/admin/teacher-verifications/$teacherId/history'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map(
          (item) => TeacherVerificationAuditEntry.fromJson(
            item as Map<String, dynamic>,
          ),
        )
        .toList();
  }

  Future<Map<String, dynamic>> getAdminIntegrationStatus({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/admin/integrations/status'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : <String, dynamic>{};
  }

  Future<Map<String, Map<String, dynamic>>> getAdminAlertAcknowledgements({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/admin/alerts/acknowledgements'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    final out = <String, Map<String, dynamic>>{};
    for (final row in data) {
      if (row is! Map<String, dynamic>) continue;
      final key = row['alert_key']?.toString().trim().toLowerCase() ?? '';
      if (key.isEmpty) continue;
      out[key] = row;
    }
    return out;
  }

  Future<void> acknowledgeAdminAlert({
    required String accessToken,
    required String alertKey,
    String? note,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/v1/admin/alerts/acknowledgements'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'alert_key': alertKey, 'note': note}),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> unacknowledgeAdminAlert({
    required String accessToken,
    required String alertKey,
  }) async {
    await _sendRequest(
      () => http
          .delete(
            _uri('/v1/admin/alerts/acknowledgements/$alertKey'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> markNotificationRead({
    required String accessToken,
    required String notificationId,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/v1/notifications/$notificationId/read'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> deleteDocument({
    required String accessToken,
    required String documentId,
  }) async {
    await _sendRequest(
      () => http
          .delete(
            _uri('/documents/$documentId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<void> deleteGeneration({
    required String accessToken,
    required String generationId,
  }) async {
    await _sendRequest(
      () => http
          .delete(
            _uri('/generations/$generationId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<List<SubscriptionPlan>> listSubscriptionPlans() async {
    final response = await _sendRequest(
      () => http
          .get(_uri('/subscriptions/plans'), headers: _jsonHeaders())
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => SubscriptionPlan.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<Map<String, dynamic>> mySubscription({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/subscriptions/me'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> subscriptionEntitlement({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/subscriptions/entitlement'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> startSubscriptionCheckout({
    required String accessToken,
    required String planId,
    required String phoneNumber,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/subscriptions/checkout'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'plan_id': planId, 'phone_number': phoneNumber}),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<Map<String, dynamic>> subscriptionPaymentStatus({
    required String accessToken,
    required String checkoutRequestId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/subscriptions/payment/$checkoutRequestId'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<void> logout({
    required String accessToken,
    String? refreshToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/auth/logout'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({'refresh_token': refreshToken}),
          )
          .timeout(_requestTimeout),
    );
    _parseJson(response);
  }

  Future<TopicListResponse> listTopicSuggestions({
    required String accessToken,
    required String category,
    String sort = 'top',
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri(
              '/v1/topics?category=${Uri.encodeQueryComponent(category)}&sort=${Uri.encodeQueryComponent(sort)}',
            ),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return TopicListResponse.fromJson(data as Map<String, dynamic>);
  }

  Future<TopicSuggestion> createTopicSuggestion({
    required String accessToken,
    required String title,
    String? description,
    required String category,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/topics'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'title': title,
              'description': description,
              'category': category,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return TopicSuggestion.fromJson(data as Map<String, dynamic>);
  }

  Future<int> upvoteTopicSuggestion({
    required String accessToken,
    required String topicId,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/topics/$topicId/upvote'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as Map<String, dynamic>;
    return (data['upvote_count'] as num?)?.toInt() ?? 0;
  }

  Future<ClassSession> createClassFromTopic({
    required String accessToken,
    required String topicId,
    String? title,
    String? description,
    required String meetingLink,
    required DateTime scheduledStartAt,
    required DateTime scheduledEndAt,
    required int feeKes,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/topics/$topicId/create-class'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'title': title,
              'description': description,
              'meeting_link': meetingLink,
              'scheduled_start_at': scheduledStartAt.toUtc().toIso8601String(),
              'scheduled_end_at': scheduledEndAt.toUtc().toIso8601String(),
              'fee_kes': feeKes,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return ClassSession.fromJson(data as Map<String, dynamic>);
  }

  Future<List<PrivateTutorProfile>> listPrivateTutors({
    required String accessToken,
    int limit = 20,
    String? city,
  }) async {
    final cityQuery = city == null || city.trim().isEmpty
        ? ''
        : '&city=${Uri.encodeQueryComponent(city.trim())}';
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/private-tutors?limit=$limit$cityQuery'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => PrivateTutorProfile.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<PrivateTutorBookingIntent> privateTutorBookingIntent({
    required String accessToken,
    required String tutorId,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/private-tutors/$tutorId/booking-intent'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return PrivateTutorBookingIntent.fromJson(data as Map<String, dynamic>);
  }

  Future<Map<String, dynamic>> privateTutorsHealth({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/private-tutors/health'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : <String, dynamic>{};
  }

  Future<List<TopicAbuseEvent>> listTopicAbuseEvents({
    required String accessToken,
    int limit = 100,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/topics/moderation/abuse-events?limit=$limit'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => TopicAbuseEvent.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<List<TopicFlaggedItem>> listFlaggedTopics({
    required String accessToken,
    int limit = 100,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/topics/moderation/flagged?limit=$limit'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as List<dynamic>;
    return data
        .map((item) => TopicFlaggedItem.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<void> resolveFlaggedTopic({
    required String accessToken,
    required String topicId,
  }) async {
    await _sendRequest(
      () => http
          .post(
            _uri('/v1/topics/$topicId/moderation/resolve'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
  }

  Future<AdminDashboardSummary> getAdminDashboardSummary({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/admin/dashboard-summary'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return AdminDashboardSummary.fromJson(data as Map<String, dynamic>);
  }

  Future<Map<String, dynamic>> requestPlatformWithdrawal({
    required String accessToken,
    required int amountKes,
    String? phoneNumber,
    String? note,
  }) async {
    final response = await _sendRequest(
      () => http
          .post(
            _uri('/v1/admin/platform-withdrawals'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode({
              'amount_kes': amountKes,
              'phone_number': phoneNumber,
              'note': note,
            }),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return data is Map<String, dynamic> ? data : {};
  }

  Future<AdminRuntimeSettings> getAdminRuntimeSettings({
    required String accessToken,
  }) async {
    final response = await _sendRequest(
      () => http
          .get(
            _uri('/v1/admin/runtime-settings'),
            headers: _jsonHeaders(accessToken: accessToken),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response);
    return AdminRuntimeSettings.fromJson(data as Map<String, dynamic>);
  }

  Future<AdminRuntimeSettings> updateAdminRuntimeSettings({
    required String accessToken,
    required Map<String, dynamic> settings,
  }) async {
    final response = await _sendRequest(
      () => http
          .put(
            _uri('/v1/admin/runtime-settings'),
            headers: _jsonHeaders(accessToken: accessToken),
            body: jsonEncode(settings),
          )
          .timeout(_requestTimeout),
    );
    final data = _parseJson(response) as Map<String, dynamic>;
    return AdminRuntimeSettings.fromJson(
      (data['settings'] as Map<String, dynamic>?) ?? const {},
    );
  }

  TokenResponse _parseTokenResponse(http.Response response) {
    final data = _parseJson(response);
    return TokenResponse.fromJson(data);
  }

  Map<String, String> _authHeaders(String token) => {
    'Authorization': 'Bearer $token',
  };

  Map<String, String> _jsonHeaders({String? accessToken}) => {
    if (accessToken != null) 'Authorization': 'Bearer $accessToken',
    'Content-Type': 'application/json',
  };

  dynamic _parseJson(http.Response response) {
    try {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final message = _extractError(response.body);
        throw ApiException(message, statusCode: response.statusCode);
      }
      if (response.body.isEmpty) {
        return {};
      }
      return jsonDecode(response.body) as dynamic;
    } on FormatException {
      throw ApiException('Server returned malformed response.');
    }
  }

  String _extractError(String body) {
    try {
      final data = jsonDecode(body) as Map<String, dynamic>;
      return data['detail']?.toString() ?? 'Request failed';
    } catch (_) {
      return body.isEmpty ? 'Request failed' : body;
    }
  }

  Future<http.Response> _sendRequest(
    Future<http.Response> Function() request, {
    String? timeoutMessage,
    String? networkMessage,
  }) async {
    try {
      return await request();
    } on TimeoutException {
      throw ApiException(
        timeoutMessage ??
            'Request timed out. Check your connection and try again.',
      );
    } on http.ClientException {
      throw ApiException(
        networkMessage ?? 'Network error. Unable to reach the server.',
      );
    }
  }

  Future<http.StreamedResponse> _sendStreamedRequest(
    Future<http.StreamedResponse> Function() request,
  ) async {
    try {
      return await request();
    } on TimeoutException {
      throw ApiException(
        'Upload timed out. Please retry on a stronger connection.',
      );
    } on http.ClientException {
      throw ApiException('Network error during upload. Please try again.');
    }
  }
}
