import 'package:flutter/material.dart';
import '../theme/app_colors.dart';
import '../theme/tokens.dart';

class SkeletonBox extends StatefulWidget {
  const SkeletonBox({
    super.key,
    this.height = 14,
    this.width,
    this.borderRadius = AppTokens.radiusSm,
  });

  final double height;
  final double? width;
  final double borderRadius;

  @override
  State<SkeletonBox> createState() => _SkeletonBoxState();
}

class _SkeletonBoxState extends State<SkeletonBox>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1100),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        final slide = ( _controller.value * 2 ) - 1; // -1 to 1
        return ClipRRect(
          borderRadius: BorderRadius.circular(widget.borderRadius),
          child: Stack(
            children: [
              Container(
                height: widget.height,
                width: widget.width,
                color: Colors.white.withValues(alpha: 0.04),
              ),
              FractionallySizedBox(
                widthFactor: 0.4,
                child: Transform.translate(
                  offset: Offset(slide * (widget.width ?? MediaQuery.of(context).size.width) , 0),
                  child: Container(
                    height: widget.height,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Colors.white.withValues(alpha: 0.02),
                          Colors.white.withValues(alpha: 0.18),
                          Colors.white.withValues(alpha: 0.02),
                        ],
                        begin: Alignment.centerLeft,
                        end: Alignment.centerRight,
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
