import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../widgets/exam_os_logo.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.onComplete});

  final VoidCallback onComplete;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen>
    with SingleTickerProviderStateMixin {
  final PageController _pageController = PageController();
  late final AnimationController _orbController;
  int _index = 0;

  static const List<_SlideData> _slides = [
    _SlideData(
      title: 'Upload Once, Learn Faster',
      subtitle:
          'Bring your PDFs, DOCX, and notes. The platform turns them into structured study material instantly.',
      icon: Icons.upload_file_rounded,
      accent: AppColors.primary,
    ),
    _SlideData(
      title: 'Generate Smart Assessments',
      subtitle:
          'Create quizzes, exams, summaries, and concept maps from your own documents with adaptive difficulty.',
      icon: Icons.auto_awesome_rounded,
      accent: AppColors.electric,
    ),
    _SlideData(
      title: 'Track Real Progress',
      subtitle:
          'See how your study assets and AI generations grow over time with a live dashboard and library history.',
      icon: Icons.insights_rounded,
      accent: AppColors.accent,
    ),
  ];

  @override
  void initState() {
    super.initState();
    _orbController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 6),
    )..repeat();
  }

  @override
  void dispose() {
    _orbController.dispose();
    _pageController.dispose();
    super.dispose();
  }

  void _next() {
    if (_index == _slides.length - 1) {
      widget.onComplete();
      return;
    }
    _pageController.nextPage(
      duration: const Duration(milliseconds: 320),
      curve: Curves.easeOutCubic,
    );
  }

  @override
  Widget build(BuildContext context) {
    final isLast = _index == _slides.length - 1;
    return Scaffold(
      body: Stack(
        children: [
          const _OnboardingBackground(),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 16, 20, 20),
              child: Column(
                children: [
                  Row(
                    children: [
                      const Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          ExamOsLogo(size: 30),
                          SizedBox(width: 8),
                          Text(
                            'Exam OS',
                            style: TextStyle(
                              fontSize: 22,
                              fontWeight: FontWeight.w800,
                              letterSpacing: -0.3,
                            ),
                          ),
                          SizedBox(width: 6),
                          Text(
                            'by EdTech Intelligence',
                            style: TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                      const Spacer(),
                      TextButton(
                        onPressed: widget.onComplete,
                        child: const Text('Skip'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: PageView.builder(
                      controller: _pageController,
                      itemCount: _slides.length,
                      onPageChanged: (value) => setState(() => _index = value),
                      itemBuilder: (context, i) {
                        final slide = _slides[i];
                        return _SlideCard(
                          slide: slide,
                          orbController: _orbController,
                        );
                      },
                    ),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: List.generate(
                      _slides.length,
                      (i) => AnimatedContainer(
                        duration: const Duration(milliseconds: 220),
                        margin: const EdgeInsets.symmetric(horizontal: 4),
                        width: i == _index ? 26 : 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: i == _index
                              ? AppColors.primary
                              : Colors.white.withValues(alpha: 0.25),
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  GradientButton(
                    label: isLast ? 'Get Started' : 'Continue',
                    icon: isLast
                        ? Icons.rocket_launch_rounded
                        : Icons.arrow_forward_rounded,
                    onPressed: _next,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SlideData {
  const _SlideData({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.accent,
  });

  final String title;
  final String subtitle;
  final IconData icon;
  final Color accent;
}

class _SlideCard extends StatelessWidget {
  const _SlideCard({
    required this.slide,
    required this.orbController,
  });

  final _SlideData slide;
  final AnimationController orbController;

  @override
  Widget build(BuildContext context) {
    return GlassContainer(
      borderRadius: 28,
      padding: const EdgeInsets.fromLTRB(18, 24, 18, 20),
      child: Column(
        children: [
          const SizedBox(height: 10),
          AnimatedBuilder(
            animation: orbController,
            builder: (context, child) {
              final angle = orbController.value * math.pi * 2;
              return Transform.rotate(
                angle: angle,
                child: child,
              );
            },
            child: Container(
              width: 190,
              height: 190,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: SweepGradient(
                  colors: [
                    slide.accent.withValues(alpha: 0.9),
                    AppColors.primary.withValues(alpha: 0.9),
                    AppColors.indigo.withValues(alpha: 0.9),
                    slide.accent.withValues(alpha: 0.9),
                  ],
                ),
                boxShadow: [
                  BoxShadow(
                    color: slide.accent.withValues(alpha: 0.35),
                    blurRadius: 26,
                    spreadRadius: 4,
                  ),
                ],
              ),
              child: Center(
                child: Container(
                  width: 132,
                  height: 132,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: AppColors.backgroundDeep.withValues(alpha: 0.88),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.18),
                    ),
                  ),
                  child: Icon(slide.icon, color: Colors.white, size: 52),
                ),
              ),
            ),
          ),
          const SizedBox(height: 24),
          Text(
            slide.title,
            textAlign: TextAlign.center,
            style: const TextStyle(
              fontSize: 28,
              height: 1.1,
              letterSpacing: -0.4,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 14),
          Text(
            slide.subtitle,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 14,
              height: 1.45,
            ),
          ),
        ],
      ),
    );
  }
}

class _OnboardingBackground extends StatelessWidget {
  const _OnboardingBackground();

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
        children: [
          Positioned(
            top: -80,
            right: -90,
            child: _GlowBlob(color: AppColors.primary.withValues(alpha: 0.2)),
          ),
          Positioned(
            bottom: -110,
            left: -120,
            child: _GlowBlob(color: AppColors.electric.withValues(alpha: 0.16)),
          ),
        ],
      ),
    );
  }
}

class _GlowBlob extends StatelessWidget {
  const _GlowBlob({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 280,
      height: 280,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [
          BoxShadow(
            color: color,
            blurRadius: 140,
            spreadRadius: 22,
          ),
        ],
      ),
    );
  }
}
