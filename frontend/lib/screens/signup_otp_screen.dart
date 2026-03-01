import 'package:flutter/material.dart';

import '../models/models.dart';
import '../services/api_client.dart';
import '../theme/app_colors.dart';
import '../widgets/glass_container.dart';
import '../widgets/gradient_button.dart';

class SignupOtpScreen extends StatefulWidget {
  const SignupOtpScreen({
    super.key,
    required this.apiClient,
    required this.challenge,
    required this.onVerified,
  });

  final ApiClient apiClient;
  final SignupChallenge challenge;
  final ValueChanged<Session> onVerified;

  @override
  State<SignupOtpScreen> createState() => _SignupOtpScreenState();
}

class _SignupOtpScreenState extends State<SignupOtpScreen> {
  final _otpController = TextEditingController();
  bool _submitting = false;
  bool _resending = false;
  String? _error;
  String? _message;

  @override
  void initState() {
    super.initState();
    _message = widget.challenge.message;
  }

  @override
  void dispose() {
    _otpController.dispose();
    super.dispose();
  }

  Future<void> _verify() async {
    if (_submitting) return;
    final otp = _otpController.text.trim();
    if (otp.length < 4) {
      setState(() => _error = 'Enter the OTP sent to your email.');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final token = await widget.apiClient.verifySignupOtp(
        signupId: widget.challenge.signupId,
        otp: otp,
      );
      if (!mounted) return;
      widget.onVerified(token.toSession());
      Navigator.of(context).popUntil((route) => route.isFirst);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Verification failed. Try again.');
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _resend() async {
    if (_resending) return;
    setState(() {
      _resending = true;
      _error = null;
    });
    try {
      await widget.apiClient.resendSignupOtp(signupId: widget.challenge.signupId);
      if (!mounted) return;
      setState(() => _message = 'A new OTP has been sent to your email.');
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Could not resend OTP right now.');
    } finally {
      if (mounted) setState(() => _resending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Verify Email')),
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
              GlassContainer(
                borderRadius: 22,
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Almost done',
                      style: TextStyle(fontWeight: FontWeight.w800, fontSize: 18),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      _message ?? 'Enter the OTP we sent to your email.',
                      style: const TextStyle(color: AppColors.textMuted),
                    ),
                    const SizedBox(height: 14),
                    TextField(
                      controller: _otpController,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(
                        labelText: 'One-Time Password',
                        hintText: 'Enter OTP',
                        suffixIcon: Icon(Icons.verified_user_outlined),
                      ),
                    ),
                    if ((_error ?? '').isNotEmpty) ...[
                      const SizedBox(height: 10),
                      Text(_error!, style: const TextStyle(color: Colors.redAccent)),
                    ],
                    const SizedBox(height: 14),
                    GradientButton(
                      label: 'Verify & Continue',
                      icon: Icons.check_circle_outline_rounded,
                      onPressed: _verify,
                      isLoading: _submitting,
                    ),
                    const SizedBox(height: 8),
                    Align(
                      alignment: Alignment.centerRight,
                      child: TextButton(
                        onPressed: _resending ? null : _resend,
                        child: Text(_resending ? 'Resending...' : 'Resend OTP'),
                      ),
                    ),
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
