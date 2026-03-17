import 'package:flutter/material.dart';

class AppColors {
  // Core brand palette inspired by the provided UI reference.
  static const Color primary = Color(0xFFEC5B13); // vibrant orange
  static const Color accent = Color(0xFFA855F7); // orchid purple
  static const Color electric = Color(0xFFD946EF); // magenta glow
  static const Color indigo = Color(0xFF2A2146);

  // Surfaces + backgrounds (dark-first experience).
  static const Color backgroundDark = Color(0xFF0F0906);
  static const Color backgroundDeep = Color(0xFF0B0503);
  static const Color surfaceDark = Color(0xFF160F0D);
  static const Color surfaceElevated = Color(0xFF1E1512);
  static const Color surfaceLight = Color(0xFFF8F6F6);

  // Glassmorphism helpers.
  static const Color glass = Color.fromRGBO(255, 255, 255, 0.05);
  static const Color glassBorder = Color.fromRGBO(255, 255, 255, 0.12);

  // Text.
  static const Color textPrimary = Color(0xFFF7F1EA);
  static const Color textMuted = Color(0xFFB6AAA2);
}
