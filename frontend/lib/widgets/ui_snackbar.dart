import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/tokens.dart';

enum UiSnackType { info, success, error }

class UiSnackbar {
  static void show(
    BuildContext context, {
    required String message,
    UiSnackType type = UiSnackType.info,
  }) {
    final Color accent;
    final IconData icon;
    switch (type) {
      case UiSnackType.success:
        accent = Colors.tealAccent.shade200;
        icon = Icons.check_circle_rounded;
        break;
      case UiSnackType.error:
        accent = Colors.redAccent.shade200;
        icon = Icons.error_rounded;
        break;
      case UiSnackType.info:
      default:
        accent = AppColors.primary;
        icon = Icons.info_rounded;
    }

    final snackBar = SnackBar(
      margin: const EdgeInsets.all(AppTokens.spaceMd),
      behavior: SnackBarBehavior.floating,
      backgroundColor: AppColors.surfaceElevated.withValues(alpha: 0.95),
      content: Row(
        children: [
          Icon(icon, color: accent, size: 20),
          const SizedBox(width: AppTokens.spaceSm),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
        ],
      ),
    );

    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(snackBar);
  }
}
