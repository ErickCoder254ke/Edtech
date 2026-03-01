import 'package:flutter/material.dart';

import '../theme/app_colors.dart';

class ExamOsLogo extends StatelessWidget {
  const ExamOsLogo({
    super.key,
    this.size = 88,
    this.showWordmark = false,
    this.showTagline = false,
  });

  final double size;
  final bool showWordmark;
  final bool showTagline;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          width: size,
          height: size,
          child: Stack(
            alignment: Alignment.center,
            children: [
              Container(
                width: size * 0.95,
                height: size * 0.95,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: RadialGradient(
                    colors: [
                      const Color(0xFF0C1640).withValues(alpha: 0.95),
                      const Color(0xFF070D2C).withValues(alpha: 0.8),
                      Colors.transparent,
                    ],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: AppColors.primary.withValues(alpha: 0.35),
                      blurRadius: 28,
                      spreadRadius: 2,
                    ),
                  ],
                ),
              ),
              CustomPaint(
                size: Size(size * 0.72, size * 0.72),
                painter: _ExamOsMarkPainter(),
              ),
            ],
          ),
        ),
        if (showWordmark) ...[
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _GradientText(
                'Exam OS',
                style: const TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w900,
                  letterSpacing: -0.2,
                ),
              ),
              if (showTagline)
                const Text(
                  'by EdTech Intelligence',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                ),
            ],
          ),
        ],
      ],
    );
  }
}

class _ExamOsMarkPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final shader = const LinearGradient(
      colors: [Color(0xFF1ED8FF), Color(0xFF5A4DFF), Color(0xFFFF2D8A)],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ).createShader(Offset.zero & size);

    final paint = Paint()
      ..shader = shader
      ..style = PaintingStyle.fill;

    final topBar = Path()
      ..moveTo(size.width * 0.08, size.height * 0.18)
      ..lineTo(size.width * 0.83, size.height * 0.18)
      ..lineTo(size.width * 0.67, size.height * 0.31)
      ..lineTo(size.width * 0.08, size.height * 0.31)
      ..close();
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        Rect.fromLTWH(size.width * 0.08, size.height * 0.18, size.width * 0.75, size.height * 0.13),
        Radius.circular(size.width * 0.08),
      ),
      paint,
    );
    canvas.drawPath(topBar, paint);

    final middle = Path()
      ..moveTo(size.width * 0.08, size.height * 0.43)
      ..lineTo(size.width * 0.44, size.height * 0.43)
      ..lineTo(size.width * 0.60, size.height * 0.57)
      ..lineTo(size.width * 0.92, size.height * 0.30)
      ..lineTo(size.width * 0.62, size.height * 0.72)
      ..lineTo(size.width * 0.38, size.height * 0.52)
      ..lineTo(size.width * 0.08, size.height * 0.52)
      ..close();
    canvas.drawPath(middle, paint);

    final bottom = Path()
      ..moveTo(size.width * 0.08, size.height * 0.70)
      ..lineTo(size.width * 0.54, size.height * 0.70)
      ..lineTo(size.width * 0.69, size.height * 0.58)
      ..lineTo(size.width * 0.84, size.height * 0.58)
      ..lineTo(size.width * 0.79, size.height * 0.84)
      ..lineTo(size.width * 0.18, size.height * 0.84)
      ..lineTo(size.width * 0.08, size.height * 0.77)
      ..close();
    canvas.drawPath(bottom, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _GradientText extends StatelessWidget {
  const _GradientText(this.text, {required this.style});

  final String text;
  final TextStyle style;

  @override
  Widget build(BuildContext context) {
    return ShaderMask(
      shaderCallback: (bounds) => const LinearGradient(
        colors: [Color(0xFFFFFFFF), Color(0xFFB4BDFF), Color(0xFFFF4CA2)],
        begin: Alignment.centerLeft,
        end: Alignment.centerRight,
      ).createShader(bounds),
      child: Text(
        text,
        style: style.copyWith(color: Colors.white),
      ),
    );
  }
}
