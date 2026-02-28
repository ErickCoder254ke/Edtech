class Session {
  Session({
    required this.accessToken,
    required this.refreshToken,
    required this.user,
  });

  final String accessToken;
  final String refreshToken;
  final User user;

  Session copyWith({String? accessToken, String? refreshToken, User? user}) {
    return Session(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      user: user ?? this.user,
    );
  }

  Map<String, dynamic> toJson() => {
    'access_token': accessToken,
    'refresh_token': refreshToken,
    'user': user.toJson(),
  };

  factory Session.fromJson(Map<String, dynamic> json) {
    return Session(
      accessToken: json['access_token'] as String? ?? '',
      refreshToken: json['refresh_token'] as String? ?? '',
      user: User.fromJson(json['user'] as Map<String, dynamic>? ?? {}),
    );
  }
}

class User {
  User({
    required this.id,
    required this.email,
    required this.fullName,
    required this.role,
    required this.createdAt,
  });

  final String id;
  final String email;
  final String fullName;
  final String role;
  final DateTime createdAt;

  User copyWith({
    String? id,
    String? email,
    String? fullName,
    String? role,
    DateTime? createdAt,
  }) {
    return User(
      id: id ?? this.id,
      email: email ?? this.email,
      fullName: fullName ?? this.fullName,
      role: role ?? this.role,
      createdAt: createdAt ?? this.createdAt,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'email': email,
    'full_name': fullName,
    'role': role,
    'created_at': createdAt.toIso8601String(),
  };

  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      id: json['id'] as String? ?? '',
      email: json['email'] as String? ?? '',
      fullName: json['full_name'] as String? ?? '',
      role: json['role'] as String? ?? 'student',
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
    );
  }
}

class TokenResponse {
  TokenResponse({
    required this.accessToken,
    required this.refreshToken,
    required this.tokenType,
    required this.user,
  });

  final String accessToken;
  final String refreshToken;
  final String tokenType;
  final User user;

  factory TokenResponse.fromJson(Map<String, dynamic> json) {
    return TokenResponse(
      accessToken: json['access_token'] as String? ?? '',
      refreshToken: json['refresh_token'] as String? ?? '',
      tokenType: json['token_type'] as String? ?? 'bearer',
      user: User.fromJson(json['user'] as Map<String, dynamic>? ?? {}),
    );
  }

  Session toSession() =>
      Session(accessToken: accessToken, refreshToken: refreshToken, user: user);
}

class SignupChallenge {
  SignupChallenge({required this.signupId, required this.message});

  final String signupId;
  final String message;

  factory SignupChallenge.fromJson(Map<String, dynamic> json) {
    return SignupChallenge(
      signupId: json['signup_id'] as String? ?? '',
      message: json['message'] as String? ?? 'Verification code sent.',
    );
  }
}

class DocumentMetadata {
  DocumentMetadata({
    required this.id,
    required this.userId,
    required this.filename,
    required this.fileType,
    required this.filePath,
    required this.fileSize,
    required this.totalChunks,
    required this.keywords,
    required this.uploadedAt,
  });

  final String id;
  final String userId;
  final String filename;
  final String fileType;
  final String filePath;
  final int fileSize;
  final int totalChunks;
  final List<String> keywords;
  final DateTime uploadedAt;

  factory DocumentMetadata.fromJson(Map<String, dynamic> json) {
    return DocumentMetadata(
      id: json['id'] as String? ?? '',
      userId: json['user_id'] as String? ?? '',
      filename: json['filename'] as String? ?? '',
      fileType: json['file_type'] as String? ?? '',
      filePath: json['file_path'] as String? ?? '',
      fileSize: (json['file_size'] as num?)?.toInt() ?? 0,
      totalChunks: (json['total_chunks'] as num?)?.toInt() ?? 0,
      keywords: (json['keywords'] as List<dynamic>? ?? const [])
          .map((e) => e.toString())
          .toList(),
      uploadedAt:
          DateTime.tryParse(json['uploaded_at'] as String? ?? '') ??
          DateTime.now(),
    );
  }
}

class GenerationRequest {
  GenerationRequest({
    required this.documentIds,
    required this.generationType,
    this.topic,
    this.difficulty = 'medium',
    this.marks,
    this.questionTypes,
    this.numQuestions = 10,
    this.additionalInstructions,
  });

  final List<String> documentIds;
  final String generationType;
  final String? topic;
  final String difficulty;
  final int? marks;
  final List<String>? questionTypes;
  final int? numQuestions;
  final String? additionalInstructions;

  Map<String, dynamic> toJson() {
    return {
      'document_ids': documentIds,
      'generation_type': generationType,
      'topic': topic,
      'difficulty': difficulty,
      'marks': marks,
      'question_types': questionTypes,
      'num_questions': numQuestions,
      'additional_instructions': additionalInstructions,
    }..removeWhere((key, value) => value == null);
  }
}

class GenerationResponse {
  GenerationResponse({
    required this.id,
    required this.userId,
    required this.generationType,
    required this.content,
    required this.createdAt,
  });

  final String id;
  final String userId;
  final String generationType;
  final Map<String, dynamic> content;
  final DateTime createdAt;

  factory GenerationResponse.fromJson(Map<String, dynamic> json) {
    return GenerationResponse(
      id: json['id'] as String? ?? '',
      userId: json['user_id'] as String? ?? '',
      generationType: json['generation_type'] as String? ?? '',
      content: json['content'] as Map<String, dynamic>? ?? {},
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
    );
  }
}

class GenerationJobResponse {
  GenerationJobResponse({
    required this.jobId,
    required this.status,
    required this.estimatedTime,
  });

  final String jobId;
  final String status;
  final String estimatedTime;

  factory GenerationJobResponse.fromJson(Map<String, dynamic> json) {
    return GenerationJobResponse(
      jobId: json['job_id'] as String? ?? '',
      status: json['status'] as String? ?? 'queued',
      estimatedTime: json['estimated_time'] as String? ?? '',
    );
  }
}

class JobStatusResponse {
  JobStatusResponse({
    required this.jobId,
    required this.userId,
    required this.type,
    required this.status,
    this.progress,
    required this.createdAt,
    this.completedAt,
    this.resultReference,
    this.error,
  });

  final String jobId;
  final String userId;
  final String type;
  final String status;
  final int? progress;
  final DateTime createdAt;
  final DateTime? completedAt;
  final String? resultReference;
  final String? error;

  bool get isTerminal => status == 'completed' || status == 'failed';

  factory JobStatusResponse.fromJson(Map<String, dynamic> json) {
    return JobStatusResponse(
      jobId: json['job_id'] as String? ?? '',
      userId: json['user_id'] as String? ?? '',
      type: json['type'] as String? ?? '',
      status: json['status'] as String? ?? 'queued',
      progress: (json['progress'] as num?)?.toInt(),
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
      completedAt: DateTime.tryParse(json['completed_at'] as String? ?? ''),
      resultReference: json['result_reference'] as String?,
      error: json['error'] as String?,
    );
  }
}

class ClassSession {
  ClassSession({
    required this.id,
    required this.teacherId,
    required this.teacherName,
    required this.title,
    this.description,
    required this.meetingLink,
    required this.scheduledStartAt,
    required this.scheduledEndAt,
    required this.status,
    required this.createdAt,
    required this.feeKes,
    required this.durationMinutes,
    required this.joinCount,
    required this.joined,
    this.averageRating,
    required this.reviewCount,
  });

  final String id;
  final String teacherId;
  final String teacherName;
  final String title;
  final String? description;
  final String meetingLink;
  final DateTime scheduledStartAt;
  final DateTime scheduledEndAt;
  final String status;
  final DateTime createdAt;
  final int feeKes;
  final int durationMinutes;
  final int joinCount;
  final bool joined;
  final double? averageRating;
  final int reviewCount;

  factory ClassSession.fromJson(Map<String, dynamic> json) {
    return ClassSession(
      id: json['id'] as String? ?? '',
      teacherId: json['teacher_id'] as String? ?? '',
      teacherName: json['teacher_name'] as String? ?? 'Teacher',
      title: json['title'] as String? ?? '',
      description: json['description'] as String?,
      meetingLink: json['meeting_link'] as String? ?? '',
      scheduledStartAt:
          DateTime.tryParse(json['scheduled_start_at'] as String? ?? '') ??
          DateTime.now(),
      scheduledEndAt:
          DateTime.tryParse(json['scheduled_end_at'] as String? ?? '') ??
          DateTime.now(),
      status: json['status'] as String? ?? 'scheduled',
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
      feeKes: (json['fee_kes'] as num?)?.toInt() ?? 0,
      durationMinutes: (json['duration_minutes'] as num?)?.toInt() ?? 0,
      joinCount: (json['join_count'] as num?)?.toInt() ?? 0,
      joined: json['joined'] as bool? ?? false,
      averageRating: (json['average_rating'] as num?)?.toDouble(),
      reviewCount: (json['review_count'] as num?)?.toInt() ?? 0,
    );
  }
}

class ClassReview {
  ClassReview({
    required this.id,
    required this.classId,
    required this.studentId,
    required this.teacherId,
    required this.rating,
    this.comment,
    required this.createdAt,
  });

  final String id;
  final String classId;
  final String studentId;
  final String teacherId;
  final int rating;
  final String? comment;
  final DateTime createdAt;

  factory ClassReview.fromJson(Map<String, dynamic> json) {
    return ClassReview(
      id: json['id'] as String? ?? '',
      classId: json['class_id'] as String? ?? '',
      studentId: json['student_id'] as String? ?? '',
      teacherId: json['teacher_id'] as String? ?? '',
      rating: (json['rating'] as num?)?.toInt() ?? 0,
      comment: json['comment'] as String?,
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
    );
  }
}

class NotificationItem {
  NotificationItem({
    required this.id,
    required this.userId,
    required this.status,
    required this.message,
    required this.createdAt,
    required this.read,
    this.classId,
    this.jobId,
    this.resultReference,
    this.meetingLink,
  });

  final String id;
  final String userId;
  final String status;
  final String message;
  final DateTime createdAt;
  final bool read;
  final String? classId;
  final String? jobId;
  final String? resultReference;
  final String? meetingLink;

  factory NotificationItem.fromJson(Map<String, dynamic> json) {
    return NotificationItem(
      id: json['id'] as String? ?? '',
      userId: json['user_id'] as String? ?? '',
      status: json['status'] as String? ?? 'info',
      message: json['message'] as String? ?? '',
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
      read: json['read'] as bool? ?? false,
      classId: json['class_id'] as String?,
      jobId: json['job_id'] as String?,
      resultReference: json['result_reference'] as String?,
      meetingLink: json['meeting_link'] as String?,
    );
  }
}

class SubscriptionPlan {
  SubscriptionPlan({
    required this.planId,
    required this.name,
    required this.cycleDays,
    required this.amountKes,
    required this.generationQuota,
    this.examQuota,
    required this.discountPct,
    this.savingsLabel,
  });

  final String planId;
  final String name;
  final int cycleDays;
  final int amountKes;
  final int generationQuota;
  final int? examQuota;
  final int discountPct;
  final String? savingsLabel;

  factory SubscriptionPlan.fromJson(Map<String, dynamic> json) {
    return SubscriptionPlan(
      planId: json['plan_id'] as String? ?? '',
      name: json['name'] as String? ?? '',
      cycleDays: (json['cycle_days'] as num?)?.toInt() ?? 0,
      amountKes: (json['amount_kes'] as num?)?.toInt() ?? 0,
      generationQuota: (json['generation_quota'] as num?)?.toInt() ?? 0,
      examQuota: (json['exam_quota'] as num?)?.toInt(),
      discountPct: (json['discount_pct'] as num?)?.toInt() ?? 0,
      savingsLabel: json['savings_label'] as String?,
    );
  }
}

class TopicSuggestion {
  TopicSuggestion({
    required this.id,
    required this.title,
    required this.description,
    required this.category,
    required this.categoryLabel,
    required this.createdBy,
    required this.createdAt,
    required this.upvoteCount,
    required this.status,
    required this.userHasUpvoted,
  });

  final String id;
  final String title;
  final String? description;
  final String category;
  final String categoryLabel;
  final String createdBy;
  final DateTime createdAt;
  final int upvoteCount;
  final String status;
  final bool userHasUpvoted;

  TopicSuggestion copyWith({
    String? id,
    String? title,
    String? description,
    String? category,
    String? categoryLabel,
    String? createdBy,
    DateTime? createdAt,
    int? upvoteCount,
    String? status,
    bool? userHasUpvoted,
  }) {
    return TopicSuggestion(
      id: id ?? this.id,
      title: title ?? this.title,
      description: description ?? this.description,
      category: category ?? this.category,
      categoryLabel: categoryLabel ?? this.categoryLabel,
      createdBy: createdBy ?? this.createdBy,
      createdAt: createdAt ?? this.createdAt,
      upvoteCount: upvoteCount ?? this.upvoteCount,
      status: status ?? this.status,
      userHasUpvoted: userHasUpvoted ?? this.userHasUpvoted,
    );
  }

  factory TopicSuggestion.fromJson(Map<String, dynamic> json) {
    return TopicSuggestion(
      id: json['id'] as String? ?? '',
      title: json['title'] as String? ?? '',
      description: json['description'] as String?,
      category: json['category'] as String? ?? '',
      categoryLabel: json['category_label'] as String? ?? '',
      createdBy: json['created_by'] as String? ?? '',
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
      upvoteCount: (json['upvote_count'] as num?)?.toInt() ?? 0,
      status: json['status'] as String? ?? 'open',
      userHasUpvoted: json['user_has_upvoted'] as bool? ?? false,
    );
  }
}

class TopicListResponse {
  TopicListResponse({
    required this.items,
    required this.category,
    required this.categoryLabel,
    required this.totalSuggestions,
    required this.totalVotes,
  });

  final List<TopicSuggestion> items;
  final String category;
  final String categoryLabel;
  final int totalSuggestions;
  final int totalVotes;

  factory TopicListResponse.fromJson(Map<String, dynamic> json) {
    return TopicListResponse(
      items: (json['items'] as List<dynamic>? ?? const [])
          .map((item) => TopicSuggestion.fromJson(item as Map<String, dynamic>))
          .toList(),
      category: json['category'] as String? ?? '',
      categoryLabel: json['category_label'] as String? ?? '',
      totalSuggestions: (json['total_suggestions'] as num?)?.toInt() ?? 0,
      totalVotes: (json['total_votes'] as num?)?.toInt() ?? 0,
    );
  }
}

class TopicAbuseEvent {
  TopicAbuseEvent({
    required this.id,
    required this.eventType,
    required this.userId,
    this.suggestionId,
    this.category,
    this.ipAddress,
    this.deviceFingerprint,
    required this.details,
    required this.createdAt,
  });

  final String id;
  final String eventType;
  final String userId;
  final String? suggestionId;
  final String? category;
  final String? ipAddress;
  final String? deviceFingerprint;
  final Map<String, dynamic> details;
  final DateTime createdAt;

  factory TopicAbuseEvent.fromJson(Map<String, dynamic> json) {
    return TopicAbuseEvent(
      id: json['id'] as String? ?? '',
      eventType: json['event_type'] as String? ?? '',
      userId: json['user_id'] as String? ?? '',
      suggestionId: json['suggestion_id'] as String?,
      category: json['category'] as String?,
      ipAddress: json['ip_address'] as String?,
      deviceFingerprint: json['device_fingerprint'] as String?,
      details: (json['details'] as Map<String, dynamic>?) ?? const {},
      createdAt:
          DateTime.tryParse(json['created_at'] as String? ?? '') ??
          DateTime.now(),
    );
  }
}

class TopicFlaggedItem {
  TopicFlaggedItem({
    required this.id,
    required this.title,
    required this.category,
    required this.categoryLabel,
    required this.upvoteCount,
    required this.fraudSpikeFlag,
    this.fraudSpikeFlaggedAt,
  });

  final String id;
  final String title;
  final String category;
  final String categoryLabel;
  final int upvoteCount;
  final bool fraudSpikeFlag;
  final DateTime? fraudSpikeFlaggedAt;

  factory TopicFlaggedItem.fromJson(Map<String, dynamic> json) {
    return TopicFlaggedItem(
      id: json['id'] as String? ?? '',
      title: json['title'] as String? ?? '',
      category: json['category'] as String? ?? '',
      categoryLabel: json['category_label'] as String? ?? '',
      upvoteCount: (json['upvote_count'] as num?)?.toInt() ?? 0,
      fraudSpikeFlag: json['fraud_spike_flag'] as bool? ?? false,
      fraudSpikeFlaggedAt: DateTime.tryParse(
        json['fraud_spike_flagged_at'] as String? ?? '',
      ),
    );
  }
}

class PrivateTutorProfile {
  PrivateTutorProfile({
    required this.id,
    required this.providerId,
    required this.providerName,
    required this.headline,
    required this.bio,
    required this.priceKes,
    required this.priceUnit,
    required this.experienceYears,
    required this.qualifications,
    required this.certifications,
    required this.city,
    required this.serviceType,
    required this.availableNow,
    this.photoUrl,
    required this.bookingDeepLink,
    this.bookingWebUrl,
    required this.source,
  });

  final String id;
  final String providerId;
  final String providerName;
  final String headline;
  final String bio;
  final double priceKes;
  final String priceUnit;
  final int experienceYears;
  final String qualifications;
  final List<String> certifications;
  final String city;
  final String serviceType;
  final bool availableNow;
  final String? photoUrl;
  final String bookingDeepLink;
  final String? bookingWebUrl;
  final String source;

  factory PrivateTutorProfile.fromJson(Map<String, dynamic> json) {
    return PrivateTutorProfile(
      id: json['id'] as String? ?? '',
      providerId: json['provider_id'] as String? ?? '',
      providerName: json['provider_name'] as String? ?? '',
      headline: json['headline'] as String? ?? '',
      bio: json['bio'] as String? ?? '',
      priceKes: (json['price_kes'] as num?)?.toDouble() ?? 0,
      priceUnit: json['price_unit'] as String? ?? '',
      experienceYears: (json['experience_years'] as num?)?.toInt() ?? 0,
      qualifications: json['qualifications'] as String? ?? '',
      certifications: (json['certifications'] as List<dynamic>? ?? const [])
          .map((e) => e.toString())
          .toList(),
      city: json['city'] as String? ?? '',
      serviceType: json['service_type'] as String? ?? '',
      availableNow: json['available_now'] as bool? ?? false,
      photoUrl: json['photo_url'] as String?,
      bookingDeepLink: json['booking_deep_link'] as String? ?? '',
      bookingWebUrl: json['booking_web_url'] as String?,
      source: json['source'] as String? ?? 'localpro_ke',
    );
  }
}

class PrivateTutorBookingIntent {
  PrivateTutorBookingIntent({
    required this.tutorId,
    required this.deepLink,
    required this.playstoreUrl,
    required this.packageName,
    this.webUrl,
  });

  final String tutorId;
  final String deepLink;
  final String playstoreUrl;
  final String packageName;
  final String? webUrl;

  factory PrivateTutorBookingIntent.fromJson(Map<String, dynamic> json) {
    return PrivateTutorBookingIntent(
      tutorId: json['tutor_id'] as String? ?? '',
      deepLink: json['deep_link'] as String? ?? '',
      playstoreUrl: json['playstore_url'] as String? ?? '',
      packageName: json['package_name'] as String? ?? '',
      webUrl: json['web_url'] as String?,
    );
  }
}

class AdminDashboardSummary {
  AdminDashboardSummary({
    required this.platformWalletBalanceKes,
    required this.platformWalletTotalEarnedKes,
    required this.platformWalletTotalWithdrawnKes,
    required this.studentsCount,
    required this.teachersCount,
    required this.adminsCount,
    required this.usersTotal,
  });

  final int platformWalletBalanceKes;
  final int platformWalletTotalEarnedKes;
  final int platformWalletTotalWithdrawnKes;
  final int studentsCount;
  final int teachersCount;
  final int adminsCount;
  final int usersTotal;

  factory AdminDashboardSummary.fromJson(Map<String, dynamic> json) {
    return AdminDashboardSummary(
      platformWalletBalanceKes:
          (json['platform_wallet_balance_kes'] as num?)?.toInt() ?? 0,
      platformWalletTotalEarnedKes:
          (json['platform_wallet_total_earned_kes'] as num?)?.toInt() ?? 0,
      platformWalletTotalWithdrawnKes:
          (json['platform_wallet_total_withdrawn_kes'] as num?)?.toInt() ?? 0,
      studentsCount: (json['students_count'] as num?)?.toInt() ?? 0,
      teachersCount: (json['teachers_count'] as num?)?.toInt() ?? 0,
      adminsCount: (json['admins_count'] as num?)?.toInt() ?? 0,
      usersTotal: (json['users_total'] as num?)?.toInt() ?? 0,
    );
  }
}

class AdminRuntimeSettings {
  AdminRuntimeSettings({
    required this.subscriptionWeeklyKes,
    required this.subscriptionMonthlyKes,
    required this.subscriptionAnnualKes,
    required this.weeklyPlanMaxExams,
    required this.monthlyPlanMaxExams,
    required this.annualPlanMaxExams,
    required this.classEscrowPlatformFeePercent,
    required this.classMinFeeKes,
    required this.classMaxFeeKes,
    required this.accountReuseGraceDays,
  });

  final int subscriptionWeeklyKes;
  final int subscriptionMonthlyKes;
  final int subscriptionAnnualKes;
  final int weeklyPlanMaxExams;
  final int monthlyPlanMaxExams;
  final int annualPlanMaxExams;
  final double classEscrowPlatformFeePercent;
  final int classMinFeeKes;
  final int classMaxFeeKes;
  final int accountReuseGraceDays;

  factory AdminRuntimeSettings.fromJson(Map<String, dynamic> json) {
    return AdminRuntimeSettings(
      subscriptionWeeklyKes: (json['subscription_weekly_kes'] as num?)?.toInt() ?? 149,
      subscriptionMonthlyKes: (json['subscription_monthly_kes'] as num?)?.toInt() ?? 499,
      subscriptionAnnualKes: (json['subscription_annual_kes'] as num?)?.toInt() ?? 4499,
      weeklyPlanMaxExams: (json['weekly_plan_max_exams'] as num?)?.toInt() ?? 2,
      monthlyPlanMaxExams: (json['monthly_plan_max_exams'] as num?)?.toInt() ?? 8,
      annualPlanMaxExams: (json['annual_plan_max_exams'] as num?)?.toInt() ?? 128,
      classEscrowPlatformFeePercent:
          (json['class_escrow_platform_fee_percent'] as num?)?.toDouble() ?? 10,
      classMinFeeKes: (json['class_min_fee_kes'] as num?)?.toInt() ?? 50,
      classMaxFeeKes: (json['class_max_fee_kes'] as num?)?.toInt() ?? 20000,
      accountReuseGraceDays: (json['account_reuse_grace_days'] as num?)?.toInt() ?? 3,
    );
  }
}
