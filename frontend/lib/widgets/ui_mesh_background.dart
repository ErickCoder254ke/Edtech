import 'package:flutter/material.dart';
import '../theme/app_colors.dart';

class UiMeshBackground extends StatelessWidget {
  const UiMeshBackground({super.key});

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
          Positioned.fill(
            child: DecoratedBox(
              decoration: BoxDecoration(
                gradient: const RadialGradient(
                  colors: [Color(0x26EC5B13), Colors.transparent],
                  radius: 0.85,
                  center: Alignment(-1.0, -1.0),
                ),
              ),
            ),
          ),
          Positioned.fill(
            child: DecoratedBox(
              decoration: const BoxDecoration(
                gradient: RadialGradient(
                  colors: [Color(0x228B5CF6), Colors.transparent],
                  radius: 0.85,
                  center: Alignment(1.0, -1.0),
                ),
              ),
            ),
          ),
          Positioned.fill(
            child: DecoratedBox(
              decoration: const BoxDecoration(
                gradient: RadialGradient(
                  colors: [Color(0x1FEC5B13), Colors.transparent],
                  radius: 0.9,
                  center: Alignment(1.0, 1.0),
                ),
              ),
            ),
          ),
          Positioned.fill(
            child: DecoratedBox(
              decoration: const BoxDecoration(
                gradient: RadialGradient(
                  colors: [Color(0x1A8B5CF6), Colors.transparent],
                  radius: 0.9,
                  center: Alignment(-1.0, 1.0),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
