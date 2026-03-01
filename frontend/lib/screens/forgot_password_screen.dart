import 'package:flutter/material.dart';

import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/exam_os_logo.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';

class ForgotPasswordScreen extends StatefulWidget {
  const ForgotPasswordScreen({
    super.key,
    required this.apiClient,
  });

  final ApiClient apiClient;

  @override
  State<ForgotPasswordScreen> createState() => _ForgotPasswordScreenState();
}

class _ForgotPasswordScreenState extends State<ForgotPasswordScreen> {
  final _emailController = TextEditingController();
  bool _isSubmitting = false;
  String? _message;
  String? _error;

  @override
  void dispose() {
    _emailController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_isSubmitting) return;
    final email = _emailController.text.trim();
    if (!email.contains('@') || !email.contains('.')) {
      setState(() {
        _error = 'Enter a valid email address.';
        _message = null;
      });
      return;
    }
    setState(() {
      _isSubmitting = true;
      _error = null;
      _message = null;
    });
    try {
      await widget.apiClient.requestPasswordReset(email: email);
      if (!mounted) return;
      setState(() {
        _message = 'If an account exists for $email, a reset link has been sent.';
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Could not send reset link. Please try again.');
    } finally {
      if (mounted) {
        setState(() => _isSubmitting = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Reset Password')),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [AppColors.backgroundDeep, AppColors.backgroundDark],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: SafeArea(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(20, 18, 20, 24),
            children: [
              const Center(child: ExamOsLogo(size: 86)),
              const SizedBox(height: 16),
              GlassContainer(
                borderRadius: 22,
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Forgot your password?',
                      style: TextStyle(fontWeight: FontWeight.w800, fontSize: 18),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Enter your account email and we will send a reset link.',
                      style: TextStyle(color: AppColors.textMuted),
                    ),
                    const SizedBox(height: 14),
                    TextField(
                      controller: _emailController,
                      keyboardType: TextInputType.emailAddress,
                      decoration: const InputDecoration(
                        labelText: 'Email Address',
                        hintText: 'you@school.edu',
                        suffixIcon: Icon(Icons.email_outlined),
                      ),
                    ),
                    const SizedBox(height: 14),
                    GradientButton(
                      label: 'Send Reset Link',
                      icon: Icons.send_rounded,
                      onPressed: _submit,
                      isLoading: _isSubmitting,
                    ),
                    if ((_error ?? '').isNotEmpty) ...[
                      const SizedBox(height: 10),
                      Text(
                        _error!,
                        style: const TextStyle(color: Colors.redAccent),
                      ),
                    ],
                    if ((_message ?? '').isNotEmpty) ...[
                      const SizedBox(height: 10),
                      Text(
                        _message!,
                        style: const TextStyle(color: AppColors.textMuted),
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
