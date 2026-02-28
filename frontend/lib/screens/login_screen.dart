import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/exam_os_logo.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';
import 'forgot_password_screen.dart';
import 'signup_otp_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({
    super.key,
    required this.apiClient,
    required this.onLogin,
  });

  final ApiClient apiClient;
  final ValueChanged<Session> onLogin;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen>
    with SingleTickerProviderStateMixin {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  final _nameController = TextEditingController();

  late final AnimationController _pulseController;
  bool _isLoading = false;
  bool _isRegister = false;
  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;
  String _selectedRole = 'student';
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 4),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_isLoading) {
      return;
    }

    FocusScope.of(context).unfocus();
    final email = _emailController.text.trim();
    final password = _passwordController.text.trim();
    final confirmPassword = _confirmPasswordController.text.trim();
    final fullName = _nameController.text.trim();

    if (email.isEmpty ||
        password.isEmpty ||
        (_isRegister && fullName.isEmpty)) {
      setState(() => _errorMessage = 'Please fill all required fields.');
      return;
    }
    if (!email.contains('@') || !email.contains('.')) {
      setState(() => _errorMessage = 'Please enter a valid email address.');
      return;
    }
    if (_isRegister && password.length < 6) {
      setState(() => _errorMessage = 'Password must be at least 6 characters.');
      return;
    }
    if (_isRegister && confirmPassword != password) {
      setState(() => _errorMessage = 'Confirm password must match password.');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      if (_isRegister) {
        final challenge = await widget.apiClient.register(
          email: email,
          password: password,
          fullName: fullName,
          role: _selectedRole,
        );
        if (!mounted) return;
        await Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => SignupOtpScreen(
              apiClient: widget.apiClient,
              challenge: challenge,
              onVerified: widget.onLogin,
            ),
          ),
        );
      } else {
        final token = await widget.apiClient.login(
          email: email,
          password: password,
        );
        widget.onLogin(token.toSession());
      }
    } on ApiException catch (e) {
      setState(() => _errorMessage = e.message);
    } catch (_) {
      setState(() => _errorMessage = 'Authentication failed. Please retry.');
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      resizeToAvoidBottomInset: true,
      body: Stack(
        children: [
          const _AuthBackground(),
          SafeArea(
            child: LayoutBuilder(
              builder: (context, constraints) {
                return SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    20,
                    16,
                    20,
                    24 + MediaQuery.of(context).viewInsets.bottom,
                  ),
                  child: ConstrainedBox(
                    constraints: BoxConstraints(
                      minHeight: constraints.maxHeight,
                    ),
                    child: Column(
                      children: [
                        const SizedBox(height: 4),
                        const _BrandHeader(),
                        const SizedBox(height: 18),
                        AnimatedBuilder(
                          animation: _pulseController,
                          builder: (_, child) {
                            final scale = 1 + (_pulseController.value * 0.08);
                            return Transform.scale(scale: scale, child: child);
                          },
                          child: const ExamOsLogo(size: 120),
                        ),
                        const SizedBox(height: 18),
                        GlassContainer(
                          borderRadius: 24,
                          padding: const EdgeInsets.all(18),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _ModeSwitch(
                                register: _isRegister,
                                onChanged: (v) {
                                  setState(() {
                                    _isRegister = v;
                                    _errorMessage = null;
                                    _passwordController.clear();
                                    _confirmPasswordController.clear();
                                    _obscurePassword = true;
                                    _obscureConfirmPassword = true;
                                  });
                                },
                              ),
                              const SizedBox(height: 16),
                              _AuthField(
                                label: 'Email',
                                controller: _emailController,
                                icon: Icons.alternate_email_rounded,
                                hint: 'you@school.edu',
                              ),
                              if (_isRegister) ...[
                                const SizedBox(height: 12),
                                _AuthField(
                                  label: 'Full Name',
                                  controller: _nameController,
                                  icon: Icons.person_outline_rounded,
                                  hint: 'Alex Rivera',
                                ),
                                const SizedBox(height: 12),
                                _RoleSelector(
                                  selectedRole: _selectedRole,
                                  onChanged: (role) =>
                                      setState(() => _selectedRole = role),
                                ),
                              ],
                              const SizedBox(height: 12),
                              _AuthField(
                                label: 'Password',
                                controller: _passwordController,
                                icon: _obscurePassword
                                    ? Icons.lock_outline_rounded
                                    : Icons.lock_open_rounded,
                                hint: '********',
                                obscure: _obscurePassword,
                                onSuffixTap: () => setState(
                                  () => _obscurePassword = !_obscurePassword,
                                ),
                              ),
                              if (_isRegister) ...[
                                const SizedBox(height: 12),
                                _AuthField(
                                  label: 'Confirm Password',
                                  controller: _confirmPasswordController,
                                  icon: _obscureConfirmPassword
                                      ? Icons.lock_outline_rounded
                                      : Icons.lock_open_rounded,
                                  hint: '********',
                                  obscure: _obscureConfirmPassword,
                                  onSuffixTap: () => setState(
                                    () => _obscureConfirmPassword =
                                        !_obscureConfirmPassword,
                                  ),
                                ),
                              ],
                              if (_errorMessage != null) ...[
                                const SizedBox(height: 12),
                                Text(
                                  _errorMessage!,
                                  style: const TextStyle(
                                    color: Colors.redAccent,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                              const SizedBox(height: 14),
                              GradientButton(
                                label: _isRegister
                                    ? 'Create Account'
                                    : 'Sign In',
                                icon: Icons.arrow_forward_rounded,
                                onPressed: _submit,
                                isLoading: _isLoading,
                              ),
                              const SizedBox(height: 8),
                              Align(
                                alignment: Alignment.centerRight,
                                child: TextButton(
                                  onPressed: () {
                                    Navigator.of(context).push(
                                      MaterialPageRoute(
                                        builder: (_) => ForgotPasswordScreen(
                                          apiClient: widget.apiClient,
                                        ),
                                      ),
                                    );
                                  },
                                  child: const Text('Forgot password?'),
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(height: 14),
                        Text(
                          _isRegister
                              ? 'By continuing, you agree to platform terms.'
                              : 'Use your registered account to continue.',
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _BrandHeader extends StatelessWidget {
  const _BrandHeader();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: const [
        Text(
          'EXAM OS',
          style: TextStyle(
            color: AppColors.accent,
            fontSize: 12,
            letterSpacing: 3.1,
            fontWeight: FontWeight.w800,
          ),
        ),
        SizedBox(height: 8),
        Text(
          'by EdTech Intelligence',
          style: TextStyle(
            fontSize: 22,
            fontWeight: FontWeight.w800,
            letterSpacing: -0.2,
          ),
        ),
      ],
    );
  }
}

class _ModeSwitch extends StatelessWidget {
  const _ModeSwitch({required this.register, required this.onChanged});

  final bool register;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 42,
      decoration: BoxDecoration(
        color: AppColors.backgroundDeep.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        children: [
          Expanded(
            child: _ModeButton(
              label: 'Sign In',
              active: !register,
              onTap: () => onChanged(false),
            ),
          ),
          Expanded(
            child: _ModeButton(
              label: 'Sign Up',
              active: register,
              onTap: () => onChanged(true),
            ),
          ),
        ],
      ),
    );
  }
}

class _ModeButton extends StatelessWidget {
  const _ModeButton({
    required this.label,
    required this.active,
    required this.onTap,
  });

  final String label;
  final bool active;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(12),
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        margin: const EdgeInsets.all(3),
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: active
              ? AppColors.primary.withValues(alpha: 0.22)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontWeight: FontWeight.w700,
            color: active ? AppColors.primary : AppColors.textMuted,
          ),
        ),
      ),
    );
  }
}

class _AuthField extends StatelessWidget {
  const _AuthField({
    required this.label,
    required this.controller,
    required this.icon,
    required this.hint,
    this.obscure = false,
    this.onSuffixTap,
  });

  final String label;
  final TextEditingController controller;
  final IconData icon;
  final String hint;
  final bool obscure;
  final VoidCallback? onSuffixTap;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label.toUpperCase(),
          style: const TextStyle(
            color: AppColors.textMuted,
            fontSize: 10,
            letterSpacing: 1.8,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          obscureText: obscure,
          decoration: InputDecoration(
            hintText: hint,
            suffixIcon: IconButton(
              onPressed: onSuffixTap,
              icon: Icon(icon, color: AppColors.textMuted),
            ),
          ),
        ),
      ],
    );
  }
}

class _RoleSelector extends StatelessWidget {
  const _RoleSelector({required this.selectedRole, required this.onChanged});

  final String selectedRole;
  final ValueChanged<String> onChanged;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'ACCOUNT TYPE',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 10,
            letterSpacing: 1.8,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 6),
        Row(
          children: [
            Expanded(
              child: _RoleChip(
                label: 'Student',
                selected: selectedRole == 'student',
                onTap: () => onChanged('student'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _RoleChip(
                label: 'Teacher',
                selected: selectedRole == 'teacher',
                onTap: () => onChanged('teacher'),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _RoleChip extends StatelessWidget {
  const _RoleChip({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(vertical: 11),
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: selected
              ? AppColors.primary.withValues(alpha: 0.22)
              : Colors.white.withValues(alpha: 0.03),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: selected
                ? AppColors.primary.withValues(alpha: 0.42)
                : Colors.white12,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontWeight: FontWeight.w700,
            color: selected ? AppColors.primary : AppColors.textMuted,
          ),
        ),
      ),
    );
  }
}

class _AuthBackground extends StatelessWidget {
  const _AuthBackground();

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
            right: -80,
            child: _GlowBlob(
              color: AppColors.electric.withValues(alpha: 0.2),
              size: 220,
            ),
          ),
          Positioned(
            bottom: -120,
            left: -100,
            child: _GlowBlob(
              color: AppColors.primary.withValues(alpha: 0.18),
              size: 280,
            ),
          ),
        ],
      ),
    );
  }
}

class _GlowBlob extends StatelessWidget {
  const _GlowBlob({required this.color, required this.size});

  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        boxShadow: [BoxShadow(color: color, blurRadius: 120, spreadRadius: 24)],
      ),
    );
  }
}
