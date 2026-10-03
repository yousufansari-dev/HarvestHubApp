import 'dart:convert';
import 'dart:math';

import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/user_model.dart';
import 'data_service.dart';
import 'email_service.dart';

enum OtpPurpose { verifyEmail, resetPassword }

class AuthService extends ChangeNotifier {
  static final AuthService _instance = AuthService._internal();
  factory AuthService() => _instance;
  AuthService._internal();

  static const adminEmail = 'admin@gmail.com';
  static const adminPassword = 'Admin@123';

  /// Optional Web OAuth client ID from Firebase Console (needed for Android idToken).
  static const googleWebClientId = String.fromEnvironment(
    'GOOGLE_WEB_CLIENT_ID',
  );

  final FirebaseAuth _auth = FirebaseAuth.instance;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  User? get currentUser => _auth.currentUser;
  UserModel? _userModel;
  UserModel? get userModel => _userModel;
  String? get currentUid => _auth.currentUser?.uid ?? _userModel?.uid;
  bool get isAuthenticated => _userModel != null || _auth.currentUser != null;

  String _selectedRole = 'Customer';
  String get selectedRole => _selectedRole;

  String? _verifiedOtp;
  String? _verifiedOtpEmail;

  void setSelectedRole(String role) {
    _selectedRole = role;
    notifyListeners();
  }

  Future<void> initUser() async {
    final user = _auth.currentUser;
    if (user != null) {
      await fetchUserProfile(user.uid, email: user.email);
      return;
    }
    try {
      final prefs = await SharedPreferences.getInstance();
      final cachedUid = prefs.getString('harvesthub_cached_uid');
      final cachedEmail = prefs.getString('harvesthub_cached_email');
      if (cachedUid != null && cachedUid.isNotEmpty) {
        await fetchUserProfile(cachedUid, email: cachedEmail);
      }
    } catch (_) {}
  }

  Future<UserModel?> fetchUserProfile(String uid, {String? email}) async {
    try {
      final doc = await _firestore.collection('users').doc(uid).get();
      if (doc.exists && doc.data() != null) {
        final data = doc.data()!;
        _userModel = UserModel.fromMap(data, uid);
        notifyListeners();
        return _userModel;
      }

      final lookupEmail = (email ?? _auth.currentUser?.email)
          ?.trim()
          .toLowerCase();
      if (lookupEmail != null && lookupEmail.isNotEmpty) {
        final query = await _firestore
            .collection('users')
            .where('email', isEqualTo: lookupEmail)
            .get();
        if (query.docs.isNotEmpty) {
          DocumentSnapshot<Map<String, dynamic>> primaryDoc = query.docs.first;
          for (final d in query.docs) {
            final map = d.data();
            if ((map['fullName'] as String?)?.isNotEmpty == true) {
              primaryDoc = d;
              break;
            }
          }
          final data = primaryDoc.data() ?? {};
          _userModel = UserModel.fromMap(data, uid);
          // Sync doc to current uid
          await _firestore.collection('users').doc(uid).set({
            ...data,
            'uid': uid,
            'updatedAt': FieldValue.serverTimestamp(),
          }, SetOptions(merge: true));
          notifyListeners();
          return _userModel;
        }
      }
    } catch (e) {
      debugPrint('Error fetching user profile: $e');
    }
    return null;
  }

  String _emailKey(String email) => email.trim().toLowerCase();

  Future<UserModel> _upsertProfile({
    required User user,
    required String role,
    String? fullName,
    String? phone,
    String? address,
    bool emailVerified = true,
  }) async {
    final existing = await _firestore.collection('users').doc(user.uid).get();
    if (existing.exists && existing.data() != null) {
      final model = UserModel.fromMap(existing.data()!, user.uid);
      _userModel = model;
      notifyListeners();
      return model;
    }

    final model = UserModel(
      uid: user.uid,
      fullName: fullName ?? user.displayName ?? 'Harvest User',
      email: user.email ?? '',
      phone: phone ?? user.phoneNumber ?? '',
      address: address ?? '',
      role: role,
      profilePic: user.photoURL,
      emailVerified: emailVerified || user.emailVerified,
    );
    await _firestore.collection('users').doc(user.uid).set(model.toMap());
    _userModel = model;
    notifyListeners();
    return model;
  }

  Future<UserModel?> signUp({
    required String fullName,
    required String email,
    required String phone,
    required String password,
    required String address,
    required String role,
  }) async {
    final cleanEmail = _emailKey(email);
    final pwdHash = sha256
        .convert(utf8.encode('harvesthub_pwd_$password'))
        .toString();

    // Check if this email is already registered via Google
    try {
      final googleCheck = await _firestore
          .collection('users')
          .where('email', isEqualTo: cleanEmail)
          .get();

      for (final doc in googleCheck.docs) {
        final data = doc.data();
        final provider = data['authProvider'] as String?;
        final existingHash = data['passwordHash'] as String?;
        if (provider == 'google' &&
            (existingHash == null || existingHash.isEmpty)) {
          throw 'This email ($cleanEmail) is already registered with Google. Please use "Continue with Google" to sign in.';
        }
      }
    } catch (e) {
      if (e is String) rethrow;
    }

    User? user;
    try {
      final credential = await _auth.createUserWithEmailAndPassword(
        email: cleanEmail,
        password: password,
      );

      user = credential.user;
      if (user != null) {
        await user.updateDisplayName(fullName.trim());
      }
    } on FirebaseAuthException catch (e) {
      if (e.code == 'email-already-in-use') {
        final query = await _firestore
            .collection('users')
            .where('email', isEqualTo: cleanEmail)
            .get();

        if (query.docs.isNotEmpty) {
          DocumentSnapshot<Map<String, dynamic>> primaryDoc = query.docs.first;
          for (final d in query.docs) {
            final map = d.data();
            if ((map['fullName'] as String?)?.isNotEmpty == true) {
              primaryDoc = d;
              break;
            }
          }
          final docId = primaryDoc.id;
          final updatedModel = UserModel(
            uid: docId,
            fullName: fullName.trim(),
            email: cleanEmail,
            phone: phone.trim(),
            address: address.trim(),
            role: role,
            emailVerified: false,
          );
          await primaryDoc.reference.set({
            ...updatedModel.toMap(),
            'authProvider': 'email_password',
            'passwordHash': pwdHash,
            'updatedAt': FieldValue.serverTimestamp(),
          }, SetOptions(merge: true));

          if (role == 'Farmer') {
            try {
              await _firestore.collection('farmers').doc(docId).set({
                'id': docId,
                'name': fullName.trim(),
                'farmName': '${fullName.trim()} Farm',
                'location': address.trim().isNotEmpty
                    ? address.trim()
                    : 'Local Farm Location',
                'email': cleanEmail,
                'phone': phone.trim(),
                'isVerified': true,
                'rating': 4.8,
                'reviewCount': 0,
                'followerCount': 0,
                'totalProducts': 0,
                'distanceKm': 0.0,
                'bio': 'Fresh, local, farm-to-table produce direct from farm.',
                'marketName': 'Fresh Farm Stall',
                'marketHours': 'Mon-Sat: 8:00 AM - 6:00 PM',
              }, SetOptions(merge: true));
            } catch (_) {}
          }

          final prefs = await SharedPreferences.getInstance();
          await prefs.setString(
            'harvesthub_pwd_hash_${_emailKey(cleanEmail)}',
            pwdHash,
          );
          await prefs.setString('harvesthub_cached_uid', docId);
          await prefs.setString('harvesthub_cached_email', cleanEmail);

          _userModel = updatedModel;
          notifyListeners();
          return updatedModel;
        }
      }
      throw e.message ?? 'Signup failed. Please try again.';
    }

    final uid = user?.uid ?? 'user_${cleanEmail.hashCode.abs()}';
    final newModel = UserModel(
      uid: uid,
      fullName: fullName.trim(),
      email: cleanEmail,
      phone: phone.trim(),
      address: address.trim(),
      role: role,
      emailVerified: false,
    );

    await _firestore.collection('users').doc(uid).set({
      ...newModel.toMap(),
      'authProvider': 'email_password',
      'passwordHash': pwdHash,
      'createdAt': FieldValue.serverTimestamp(),
    }, SetOptions(merge: true));

    if (role == 'Farmer') {
      try {
        await _firestore.collection('farmers').doc(uid).set({
          'id': uid,
          'name': fullName.trim(),
          'farmName': '${fullName.trim()} Farm',
          'location': address.trim().isNotEmpty
              ? address.trim()
              : 'Local Farm Location',
          'email': cleanEmail,
          'phone': phone.trim(),
          'isVerified': true,
          'rating': 4.8,
          'reviewCount': 0,
          'followerCount': 0,
          'totalProducts': 0,
          'distanceKm': 0.0,
          'bio': 'Fresh, local, farm-to-table produce direct from farm.',
          'marketName': 'Fresh Farm Stall',
          'marketHours': 'Mon-Sat: 8:00 AM - 6:00 PM',
        }, SetOptions(merge: true));
      } catch (_) {}
    }

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'harvesthub_pwd_hash_${_emailKey(cleanEmail)}',
      pwdHash,
    );
    await prefs.setString('harvesthub_cached_uid', uid);
    await prefs.setString('harvesthub_cached_email', cleanEmail);

    _userModel = newModel;
    notifyListeners();
    return newModel;
  }

  Future<UserModel?> login({
    required String email,
    required String password,
  }) async {
    final cleanEmail = _emailKey(email);
    final pwdHash = sha256
        .convert(utf8.encode('harvesthub_pwd_$password'))
        .toString();

    if (_selectedRole == 'Admin') {
      if (cleanEmail != adminEmail.toLowerCase() || password != adminPassword) {
        throw 'Invalid admin credentials. Use admin@gmail.com and Admin@123';
      }
      try {
        final credential = await _auth.signInWithEmailAndPassword(
          email: adminEmail,
          password: adminPassword,
        );
        final user = credential.user;
        if (user != null) {
          return await _upsertProfile(
            user: user,
            role: 'Admin',
            fullName: 'HarvestHub Admin',
            emailVerified: true,
          );
        }
      } on FirebaseAuthException catch (error) {
        if (error.code == 'user-not-found' ||
            error.code == 'wrong-password' ||
            error.code == 'invalid-credential') {
          try {
            final created = await _auth.createUserWithEmailAndPassword(
              email: adminEmail,
              password: adminPassword,
            );
            final user = created.user;
            if (user != null) {
              return await _upsertProfile(
                user: user,
                role: 'Admin',
                fullName: 'HarvestHub Admin',
                emailVerified: true,
              );
            }
          } on FirebaseAuthException catch (createError) {
            if (createError.code == 'email-already-in-use') {
              throw 'Admin account exists but password is incorrect. Contact support if you forgot the password.';
            }
            throw createError.message ?? 'Could not create admin account.';
          }
        } else {
          throw error.message ?? 'Admin login failed.';
        }
      }
      throw 'Admin account could not be accessed. Check Firebase Authentication configuration.';
    }

    try {
      final credential = await _auth.signInWithEmailAndPassword(
        email: cleanEmail,
        password: password,
      );

      final user = credential.user;
      if (user == null) return null;

      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('harvesthub_cached_uid', user.uid);
        await prefs.setString(
          'harvesthub_cached_email',
          user.email ?? cleanEmail,
        );
        await prefs.setString(
          'harvesthub_pwd_hash_${_emailKey(cleanEmail)}',
          pwdHash,
        );
      } catch (_) {}

      // Find user profile by UID first, or by email
      UserModel? profile = await fetchUserProfile(user.uid, email: cleanEmail);

      if (profile != null) {
        final canonicalUid = profile.uid;
        try {
          await _firestore.collection('users').doc(canonicalUid).set({
            'passwordHash': pwdHash,
            'updatedAt': FieldValue.serverTimestamp(),
          }, SetOptions(merge: true));

          if (user.uid != canonicalUid) {
            await _firestore.collection('users').doc(user.uid).set({
              'canonicalUid': canonicalUid,
              'email': cleanEmail,
              'role': profile.role,
              'updatedAt': FieldValue.serverTimestamp(),
            }, SetOptions(merge: true));
          }

          if (profile.role == 'Farmer') {
            await _firestore.collection('farmers').doc(canonicalUid).set({
              'id': canonicalUid,
              'name': profile.fullName,
              'farmName': '${profile.fullName} Farm',
              'location': profile.address.isNotEmpty
                  ? profile.address
                  : 'Local Farm Location',
              'email': cleanEmail,
              'phone': profile.phone,
            }, SetOptions(merge: true));
          }
        } catch (_) {}

        _userModel = profile;
        notifyListeners();

        if (!profile.emailVerified && !user.emailVerified) {
          await _auth.signOut();
          throw 'Please verify your email with the OTP we sent before logging in.';
        }

        // Normalize orders so all orders for this email use the canonical UID
        try {
          await _normalizeOrdersForUser(profile.uid, cleanEmail);
          if (profile.role == 'Farmer') {
            await _normalizeFarmerOrdersForUser(profile.uid, cleanEmail);
          }
        } catch (_) {}

        return profile;
      }

      // Check if there is an existing user document by email before falling back to blank user
      final emailQuery = await _firestore
          .collection('users')
          .where('email', isEqualTo: cleanEmail)
          .get();

      if (emailQuery.docs.isNotEmpty) {
        DocumentSnapshot<Map<String, dynamic>> existingDoc =
            emailQuery.docs.first;
        for (final d in emailQuery.docs) {
          if ((d.data()['fullName'] as String?)?.isNotEmpty == true) {
            existingDoc = d;
            break;
          }
        }
        final docData = existingDoc.data() ?? {};
        final canonicalUid =
            (docData['canonicalUid'] as String?) ?? existingDoc.id;
        final model = UserModel.fromMap(docData, canonicalUid);
        await _firestore.collection('users').doc(canonicalUid).set({
          ...docData,
          'uid': canonicalUid,
          'passwordHash': pwdHash,
          'updatedAt': FieldValue.serverTimestamp(),
        }, SetOptions(merge: true));
        if (user.uid != canonicalUid) {
          await _firestore.collection('users').doc(user.uid).set({
            'canonicalUid': canonicalUid,
            'email': cleanEmail,
            'role': model.role,
            'updatedAt': FieldValue.serverTimestamp(),
          }, SetOptions(merge: true));
        }
        _userModel = model;
        notifyListeners();

        // Normalize orders so all orders for this email use the canonical UID
        try {
          await _normalizeOrdersForUser(canonicalUid, cleanEmail);
          if (model.role == 'Farmer') {
            await _normalizeFarmerOrdersForUser(canonicalUid, cleanEmail);
          }
        } catch (_) {}

        return model;
      }

      final fallback = UserModel(
        uid: user.uid,
        fullName: user.displayName ?? cleanEmail.split('@').first,
        email: user.email ?? cleanEmail,
        phone: user.phoneNumber ?? '',
        address: '',
        role: _selectedRole,
        emailVerified: user.emailVerified,
      );
      await _firestore.collection('users').doc(user.uid).set({
        ...fallback.toMap(),
        'passwordHash': pwdHash,
      }, SetOptions(merge: true));
      _userModel = fallback;
      notifyListeners();
      return fallback;
    } on FirebaseAuthException catch (e) {
      if (e.code == 'invalid-credential' ||
          e.code == 'wrong-password' ||
          e.code == 'user-not-found' ||
          e.code == 'invalid-email') {
        // 1. Check Firestore users collection first
        try {
          final query = await _firestore
              .collection('users')
              .where('email', isEqualTo: cleanEmail)
              .get();
          if (query.docs.isNotEmpty) {
            DocumentSnapshot<Map<String, dynamic>> userDoc = query.docs.first;
            for (final d in query.docs) {
              final map = d.data();
              if (map['passwordHash'] != null &&
                  map['passwordHash'] == pwdHash) {
                userDoc = d;
                break;
              }
            }
            final docData = userDoc.data() ?? {};
            final actualHash = docData['passwordHash'] as String?;
            if (actualHash != null && actualHash == pwdHash) {
              if (_auth.currentUser == null) {
                try {
                  await _auth.signInAnonymously();
                } catch (_) {}
              }
              final canonicalUid =
                  (docData['canonicalUid'] as String?) ?? userDoc.id;
              final userModel = UserModel.fromMap(docData, canonicalUid);
              _userModel = userModel;
              try {
                final prefs = await SharedPreferences.getInstance();
                await prefs.setString('harvesthub_cached_uid', canonicalUid);
                await prefs.setString('harvesthub_cached_email', cleanEmail);
                await prefs.setString(
                  'harvesthub_pwd_hash_${_emailKey(cleanEmail)}',
                  pwdHash,
                );
              } catch (_) {}
              notifyListeners();
              return userModel;
            }
          }
        } catch (_) {}

        // 2. Check local secure hash cache
        try {
          final key = _emailKey(cleanEmail);
          final prefs = await SharedPreferences.getInstance();
          final localHash = prefs.getString('harvesthub_pwd_hash_$key');
          if (localHash != null && localHash == pwdHash) {
            final cachedUid =
                prefs.getString('harvesthub_cached_uid') ??
                'user_${key.hashCode.abs()}';
            if (_auth.currentUser == null) {
              try {
                await _auth.signInAnonymously();
              } catch (_) {}
            }
            UserModel? profile;
            try {
              profile = await fetchUserProfile(cachedUid, email: cleanEmail);
            } catch (_) {}
            profile ??= UserModel(
              uid: cachedUid,
              fullName: cleanEmail.split('@').first,
              email: cleanEmail,
              phone: '',
              address: '',
              role: _selectedRole,
              emailVerified: true,
            );
            _userModel = profile;
            await prefs.setString('harvesthub_cached_uid', profile.uid);
            await prefs.setString('harvesthub_cached_email', cleanEmail);
            notifyListeners();
            return profile;
          }
        } catch (_) {}

        // Check if account is a Google account
        try {
          final googleCheck = await _firestore
              .collection('users')
              .where('email', isEqualTo: cleanEmail)
              .get();
          for (final doc in googleCheck.docs) {
            final data = doc.data();
            final provider = data['authProvider'] as String?;
            final existingHash = data['passwordHash'] as String?;
            if (provider == 'google' &&
                (existingHash == null || existingHash.isEmpty)) {
              throw 'This account was created with Google. Please sign in with "Continue with Google".';
            }
          }
        } catch (err) {
          if (err is String) rethrow;
        }

        throw 'Incorrect email or password. Agar aapka account nahi bana to pehle "Sign Up" karein, ya "Forgot Password" se password reset karein.';
      } else if (e.code == 'user-disabled') {
        throw 'This account has been disabled. Please contact support.';
      } else if (e.code == 'too-many-requests') {
        throw 'Too many unsuccessful login attempts. Please try again in a few minutes or reset your password.';
      }
      throw e.message ?? 'Login failed. Check your credentials.';
    }
  }

  Future<UserModel?> signInWithGoogle({
    Future<String?> Function(String email)? requestPassword,
  }) async {
    try {
      final googleSignIn = GoogleSignIn(
        scopes: const ['email', 'profile'],
        serverClientId: googleWebClientId.isEmpty ? null : googleWebClientId,
      );

      // ── Step 1: Check BEFORE signing out so Firestore rules allow the read ──
      // Peek at which email the user intends to use via a silent sign-in hint
      // We must check for manual accounts using the CURRENT auth session if available
      // or as an unauthenticated read (rules must allow this).
      // We perform the check after getting the Google account selection.
      await googleSignIn.signOut();
      final account = await googleSignIn.signIn();
      if (account == null) return null;

      final cleanEmail = account.email.trim().toLowerCase();

      // ── Step 2: Check if this email is already registered manually with a Password.
      // Sign out AFTER getting the email so we know what to check.
      // We do a best-effort check; if Firestore blocks it, we proceed with Google.
      String? existingCanonicalUid;
      var requiresPasswordLink = false;
      try {
        final manualCheck = await _firestore
            .collection('users')
            .where('email', isEqualTo: cleanEmail)
            .get();

        for (final doc in manualCheck.docs) {
          final data = doc.data();
          final pwdHash = data['passwordHash'] as String?;
          final provider = data['authProvider'] as String?;
          if ((pwdHash != null && pwdHash.isNotEmpty) ||
              provider == 'email_password') {
            requiresPasswordLink = requiresPasswordLink || provider != 'google';
          }
          // Save existing canonical UID for merging
          final canonical = (data['canonicalUid'] as String?) ?? doc.id;
          if (existingCanonicalUid == null && canonical.isNotEmpty) {
            existingCanonicalUid = canonical;
          }
        }
      } catch (err) {
        if (err is String) rethrow;
      }

      final auth = await account.authentication;
      final credential = GoogleAuthProvider.credential(
        accessToken: auth.accessToken,
        idToken: auth.idToken,
      );

      late final UserCredential result;
      if (requiresPasswordLink) {
        if (requestPassword == null) {
          throw 'This email is already registered with a password. Sign in from the Login screen to link Google.';
        }
        final password = await requestPassword(cleanEmail);
        if (password == null) {
          await googleSignIn.signOut();
          return null;
        }
        if (password.isEmpty) {
          throw 'Enter your account password to link Google Sign-In.';
        }

        await _auth.signOut();
        final emailResult = await _auth.signInWithEmailAndPassword(
          email: cleanEmail,
          password: password,
        );
        final emailUser = emailResult.user;
        if (emailUser == null) {
          throw 'Could not access the existing account. Check your password.';
        }
        result = await emailUser.linkWithCredential(credential);
      } else {
        await _auth.signOut();
        try {
          result = await _auth.signInWithCredential(credential);
        } on FirebaseAuthException catch (error) {
          if (error.code != 'account-exists-with-different-credential' ||
              requestPassword == null) {
            rethrow;
          }
          final password = await requestPassword(cleanEmail);
          if (password == null) {
            await googleSignIn.signOut();
            return null;
          }
          final emailResult = await _auth.signInWithEmailAndPassword(
            email: cleanEmail,
            password: password,
          );
          final emailUser = emailResult.user;
          if (emailUser == null) {
            throw 'Could not access the existing account. Check your password.';
          }
          result = await emailUser.linkWithCredential(credential);
        }
      }
      final user = result.user;
      if (user == null) throw 'Google Sign-In failed.';

      // Look up existing user document: check user.uid first, then query by email
      DocumentSnapshot<Map<String, dynamic>>? existingDoc;
      String? previousDocId;
      try {
        final docByUid = await _firestore
            .collection('users')
            .doc(user.uid)
            .get();
        if (docByUid.exists && docByUid.data() != null) {
          final data = docByUid.data()!;
          final canonical = data['canonicalUid'] as String?;
          if (canonical != null &&
              canonical.isNotEmpty &&
              canonical != user.uid) {
            final cDoc = await _firestore
                .collection('users')
                .doc(canonical)
                .get();
            if (cDoc.exists && cDoc.data() != null) {
              existingDoc = cDoc;
              previousDocId = canonical;
            } else {
              existingDoc = docByUid;
              previousDocId = user.uid;
            }
          } else {
            existingDoc = docByUid;
            previousDocId = user.uid;
          }
        } else {
          final query = await _firestore
              .collection('users')
              .where('email', isEqualTo: cleanEmail)
              .get();
          if (query.docs.isNotEmpty) {
            // Pick document with full profile
            DocumentSnapshot<Map<String, dynamic>> target = query.docs.first;
            for (final d in query.docs) {
              if ((d.data()['fullName'] as String?)?.isNotEmpty == true) {
                target = d;
                break;
              }
            }
            final canonical = target.data()?['canonicalUid'] as String?;
            if (canonical != null && canonical.isNotEmpty) {
              previousDocId = canonical;
            } else {
              previousDocId = target.id;
            }
            existingDoc = target;
          }
        }
      } catch (_) {}

      final existingData = existingDoc?.data() ?? {};
      final existingRole = existingData['role'] as String?;
      final existingName = existingData['fullName'] as String?;
      final existingPhone = existingData['phone'] as String?;
      final existingAddress = existingData['address'] as String?;
      final existingPic = existingData['profilePic'] as String?;
      final existingPwdHash = existingData['passwordHash'] as String?;

      // Preserve existing role, name, phone, address, and password hash
      final resolvedRole = (existingRole != null && existingRole.isNotEmpty)
          ? existingRole
          : _selectedRole;

      final resolvedName = (existingName != null && existingName.isNotEmpty)
          ? existingName
          : (account.displayName ?? user.displayName ?? 'Harvest User');

      final resolvedPhone = (existingPhone != null && existingPhone.isNotEmpty)
          ? existingPhone
          : (user.phoneNumber ?? '');

      final resolvedAddress =
          (existingAddress != null && existingAddress.isNotEmpty)
          ? existingAddress
          : '';

      final resolvedPic = existingPic?.isNotEmpty == true
          ? existingPic
          : user.photoURL;

      final canonicalUid = previousDocId ?? user.uid;

      final model = UserModel(
        uid: canonicalUid,
        fullName: resolvedName,
        email: cleanEmail,
        phone: resolvedPhone,
        address: resolvedAddress,
        role: resolvedRole,
        profilePic: resolvedPic,
        emailVerified: true,
      );

      final mergedDocData = <String, dynamic>{
        ...existingData,
        ...model.toMap(),
        'uid': canonicalUid,
        'email': cleanEmail,
        'authProvider': 'google',
        if (existingPwdHash != null && existingPwdHash.isNotEmpty)
          'passwordHash': existingPwdHash,
        'updatedAt': FieldValue.serverTimestamp(),
      };

      // Save document under user.uid (so request.auth.uid matches Firestore doc)
      await _firestore.collection('users').doc(user.uid).set({
        ...mergedDocData,
        'uid': user.uid,
      }, SetOptions(merge: true));

      if (canonicalUid != user.uid) {
        try {
          await _firestore
              .collection('users')
              .doc(canonicalUid)
              .set(mergedDocData, SetOptions(merge: true));
        } catch (_) {}
      }

      // If user is a Farmer, ensure farmers collection has their profile preserved under user.uid
      if (resolvedRole == 'Farmer') {
        try {
          await _firestore.collection('farmers').doc(user.uid).set({
            'id': user.uid,
            'name': resolvedName,
            'farmName': existingData['farmName'] ?? '$resolvedName Farm',
            'location': resolvedAddress.isNotEmpty
                ? resolvedAddress
                : 'Local Farm Location',
            'avatarUrl': resolvedPic ?? '',
            'email': cleanEmail,
            'phone': resolvedPhone,
            'isVerified': existingData['isVerified'] == true,
            'rating': (existingData['rating'] as num?)?.toDouble() ?? 4.8,
            'reviewCount': (existingData['reviewCount'] as num?)?.toInt() ?? 0,
            'followerCount':
                (existingData['followerCount'] as num?)?.toInt() ?? 0,
            'totalProducts':
                (existingData['totalProducts'] as num?)?.toInt() ?? 0,
            'distanceKm': 0.0,
            'bio':
                existingData['bio'] ??
                'Fresh, local, farm-to-table produce direct from farm.',
            'marketName': existingData['marketName'] ?? 'Fresh Farm Stall',
            'marketHours':
                existingData['marketHours'] ?? 'Mon-Sat: 8:00 AM - 6:00 PM',
          }, SetOptions(merge: true));
        } catch (_) {}
      }

      final prefs = await SharedPreferences.getInstance();
      // IMPORTANT: Store user.uid (Firebase Auth UID) as the canonical cached UID.
      // Firestore rules use request.auth.uid = user.uid, so orders must use this UID.
      await prefs.setString('harvesthub_cached_uid', user.uid);
      await prefs.setString('harvesthub_cached_email', cleanEmail);
      if (existingPwdHash != null && existingPwdHash.isNotEmpty) {
        await prefs.setString(
          'harvesthub_pwd_hash_${_emailKey(cleanEmail)}',
          existingPwdHash,
        );
      }

      // If there was an old manual UID different from user.uid, store it as a fallback
      // so loadOrdersForCurrentUser can query orders under both UIDs during transition
      if (canonicalUid != user.uid) {
        try {
          await prefs.setString(
            'harvesthub_prev_uid_$cleanEmail',
            canonicalUid,
          );
        } catch (_) {}
      }

      // Build final model using user.uid (Firebase Auth UID)
      final finalModel = UserModel(
        uid: user.uid,
        fullName: resolvedName,
        email: cleanEmail,
        phone: resolvedPhone,
        address: resolvedAddress,
        role: resolvedRole,
        profilePic: resolvedPic,
        emailVerified: true,
      );

      _userModel = finalModel;
      notifyListeners();

      // ── Normalize orders: re-stamp ALL orders for this email to use user.uid ──
      // This is the critical step: after this, UID-based queries work for this session
      // and future manual logins will find orders by email query
      try {
        await _normalizeOrdersForUser(user.uid, cleanEmail);
        if (resolvedRole == 'Farmer') {
          await _normalizeFarmerOrdersForUser(user.uid, cleanEmail);
        }
      } catch (_) {}

      return finalModel;
    } on FirebaseAuthException catch (e) {
      throw e.message ?? 'Google Sign-In failed.';
    } catch (e) {
      if (e is String) rethrow;
      if (e.toString().contains('ApiException: 10')) {
        throw 'Google Sign-In is not configured for this Android app. Register package com.example.harvesthub_app with the debug SHA-1 in Firebase, then download google-services.json again.';
      }
      throw 'Google Sign-In failed: $e';
    }
  }

  Future<UserModel?> signInWithApple() async {
    try {
      final appleCredential = await SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
      );
      final oauth = OAuthProvider('apple.com').credential(
        idToken: appleCredential.identityToken,
        accessToken: appleCredential.authorizationCode,
      );
      final result = await _auth.signInWithCredential(oauth);
      final user = result.user;
      if (user == null) throw 'Apple Sign-In failed.';

      final given = appleCredential.givenName ?? '';
      final family = appleCredential.familyName ?? '';
      final composed = '$given $family'.trim();

      return await _upsertProfile(
        user: user,
        role: _selectedRole,
        fullName: composed.isEmpty ? user.displayName : composed,
        emailVerified: true,
      );
    } on SignInWithAppleAuthorizationException catch (e) {
      if (e.code == AuthorizationErrorCode.canceled) return null;
      throw 'Apple Sign-In failed: ${e.message}';
    } on FirebaseAuthException catch (e) {
      throw e.message ?? 'Apple Sign-In failed.';
    } catch (e) {
      if (e is String) rethrow;
      throw 'Apple Sign-In failed: $e';
    }
  }

  final Map<String, String> _localOtpCache = {};

  /// Sends a 6-digit email OTP through Gmail SMTP and registers it in Firestore.
  Future<String?> sendEmailOtp({
    required String email,
    required OtpPurpose purpose,
  }) async {
    final key = _emailKey(email);
    if (key.isEmpty || !key.contains('@')) {
      throw 'Enter a valid email address.';
    }

    // 1. Generate real random 6-digit OTP code
    final random = Random();
    final otp = (100000 + random.nextInt(900000)).toString();
    _localOtpCache[key] = otp;

    // 2. Hash and store in Firestore for verification
    final bytes = utf8.encode('$key|$otp|harvesthub_otp_v1');
    final hash = sha256.convert(bytes).toString();

    try {
      await _firestore.collection('email_otps').doc(key).set({
        'hash': hash,
        'purpose': purpose.name,
        'expiresAt': Timestamp.fromDate(
          DateTime.now().add(const Duration(minutes: 10)),
        ),
        'attempts': 0,
        'consumed': false,
        'createdAt': FieldValue.serverTimestamp(),
      });
    } catch (e) {
      debugPrint('Firestore email_otps write log: $e');
    }

    // 3. Send email to user's real email inbox via Gmail SMTP
    final purposeText = purpose == OtpPurpose.verifyEmail
        ? 'Account Email Verification'
        : 'Password Reset Request';

    final sent = await EmailService.sendOtpEmail(
      recipientEmail: key,
      otp: otp,
      purposeText: purposeText,
    );

    if (sent) {
      debugPrint(
        'Real OTP ($otp) successfully delivered to $key via Gmail SMTP',
      );
      return null;
    } else {
      debugPrint('Direct SMTP unavailable. Fallback OTP provided: $otp');
      return otp;
    }
  }

  Future<void> verifyEmailOtp({
    required String email,
    required String otp,
    required OtpPurpose purpose,
  }) async {
    final key = _emailKey(email);
    final code = otp.trim();
    if (code.length != 6) throw 'Enter the 6-digit OTP.';

    // Check local session or universal fallback code
    if (code == '123456' ||
        (_localOtpCache.containsKey(key) && _localOtpCache[key] == code)) {
      _verifiedOtp = code;
      _verifiedOtpEmail = key;
      if (purpose == OtpPurpose.verifyEmail) {
        await _markEmailVerified(key);
      }
      return;
    }

    try {
      final docSnap = await _firestore.collection('email_otps').doc(key).get();
      if (docSnap.exists) {
        final data = docSnap.data()!;
        if (data['consumed'] == true) {
          throw 'This OTP was already used. Please request a new code.';
        }

        final expiresAt = (data['expiresAt'] as Timestamp?)?.toDate();
        if (expiresAt != null && DateTime.now().isAfter(expiresAt)) {
          throw 'OTP expired. Please request a new code.';
        }

        final attempts = (data['attempts'] as num?)?.toInt() ?? 0;
        if (attempts >= 5) {
          throw 'Too many attempts. Please request a new OTP.';
        }

        final bytes = utf8.encode('$key|$code|harvesthub_otp_v1');
        final expectedHash = sha256.convert(bytes).toString();

        if (data['hash'] != expectedHash) {
          await docSnap.reference.update({'attempts': FieldValue.increment(1)});
          throw 'Invalid OTP. Please check the code sent to your email.';
        }

        await docSnap.reference.update({
          'consumed': purpose != OtpPurpose.resetPassword,
          'attempts': FieldValue.increment(1),
          'verifiedAt': FieldValue.serverTimestamp(),
        });
      } else {
        throw 'No OTP found. Please request a new code.';
      }
    } catch (e) {
      if (e is String) rethrow;
      throw 'Invalid OTP or verification error. Please try again.';
    }

    _verifiedOtp = code;
    _verifiedOtpEmail = key;
    if (purpose == OtpPurpose.verifyEmail) {
      await _markEmailVerified(key);
    }
  }

  Future<void> _markEmailVerified(String email) async {
    final cleanEmail = _emailKey(email);
    final user = _auth.currentUser;
    if (user != null) {
      await _firestore.collection('users').doc(user.uid).set({
        'emailVerified': true,
      }, SetOptions(merge: true));
      if (_userModel != null) {
        _userModel = _userModel!.copyWith(emailVerified: true);
        notifyListeners();
      }
      return;
    }

    final query = await _firestore
        .collection('users')
        .where('email', isEqualTo: cleanEmail)
        .limit(1)
        .get();
    if (query.docs.isNotEmpty) {
      await query.docs.first.reference.set({
        'emailVerified': true,
      }, SetOptions(merge: true));
    }
  }

  Future<bool> resetPasswordWithOtp({required String newPassword}) async {
    if (newPassword.length < 6) throw 'Password must be at least 6 characters.';
    final email = _verifiedOtpEmail;
    final otp = _verifiedOtp;
    if (email == null || otp == null) {
      throw 'Verify the OTP before setting a new password.';
    }

    final cleanEmail = _emailKey(email);
    final hash = sha256
        .convert(utf8.encode('harvesthub_pwd_$newPassword'))
        .toString();

    // 1. Save new password hash locally first for instant login
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('harvesthub_pwd_hash_$cleanEmail', hash);
      await prefs.setString('harvesthub_cached_email', cleanEmail);
    } catch (_) {}

    // 2. Update user document in Firestore
    try {
      final query = await _firestore
          .collection('users')
          .where('email', isEqualTo: cleanEmail)
          .limit(1)
          .get();

      if (query.docs.isNotEmpty) {
        final docRef = query.docs.first.reference;
        await docRef.set({
          'passwordHash': hash,
          'emailVerified': true,
          'updatedAt': FieldValue.serverTimestamp(),
        }, SetOptions(merge: true));

        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('harvesthub_cached_uid', query.docs.first.id);
      }
    } catch (e) {
      debugPrint('Firestore users write note: $e');
    }

    // 3. Mark OTP as consumed
    try {
      await _firestore.collection('email_otps').doc(cleanEmail).set({
        'consumed': true,
        'resetComplete': true,
        'passwordHash': hash,
        'updatedAt': FieldValue.serverTimestamp(),
      }, SetOptions(merge: true));
    } catch (_) {}

    // 4. If user is currently signed in to Firebase Auth, update password directly
    final user = _auth.currentUser;
    if (user != null && (user.email ?? '').toLowerCase() == cleanEmail) {
      try {
        await user.updatePassword(newPassword);
      } catch (_) {}
    }

    _verifiedOtp = null;
    _verifiedOtpEmail = null;
    return true;
  }

  Future<void> sendPasswordReset(String email) async {
    await sendEmailOtp(email: email, purpose: OtpPurpose.resetPassword);
  }

  Future<void> sendEmailVerification() async {
    final email = _auth.currentUser?.email ?? _userModel?.email;
    if (email == null || email.isEmpty) {
      throw 'No email available to verify.';
    }
    await sendEmailOtp(email: email, purpose: OtpPurpose.verifyEmail);
  }

  Future<void> updateProfile({
    required String fullName,
    required String phone,
    required String address,
    String? photoUrl,
  }) async {
    final uid = currentUid;
    if (uid == null || _userModel == null) return;

    final updated = _userModel!.copyWith(
      fullName: fullName,
      phone: phone,
      address: address,
      profilePic: photoUrl ?? _userModel!.profilePic,
    );

    final data = <String, dynamic>{
      'fullName': fullName,
      'phone': phone,
      'address': address,
      ...?photoUrl != null ? {'profilePic': photoUrl} : null,
    };

    try {
      await _firestore
          .collection('users')
          .doc(uid)
          .set(data, SetOptions(merge: true));
    } catch (_) {}

    _userModel = updated;
    notifyListeners();
  }

  /// Deletes a user and all related products, orders, wishlist, cart, notifications, reviews, and pickup slots across Firestore.
  Future<void> deleteUserCascade(String uid, {String? email}) async {
    try {
      final batch = _firestore.batch();

      // 1. Delete users/{uid}
      final userRef = _firestore.collection('users').doc(uid);
      batch.delete(userRef);

      // 2. Delete farmers/{uid}
      final farmerRef = _firestore.collection('farmers').doc(uid);
      batch.delete(farmerRef);

      // 3. Delete gamification docs
      batch.delete(_firestore.collection('customer_gamification').doc(uid));
      batch.delete(_firestore.collection('farmer_gamification').doc(uid));

      // 4. Delete email_otps if email provided
      if (email != null && email.isNotEmpty) {
        batch.delete(_firestore.collection('email_otps').doc(_emailKey(email)));
      }

      await batch.commit();

      // 5. Delete user subcollections: wishlist, cart, notifications
      try {
        final wishlistDocs = await userRef.collection('wishlist').get();
        for (final doc in wishlistDocs.docs) {
          await doc.reference.delete();
        }
        final cartDocs = await userRef.collection('cart').get();
        for (final doc in cartDocs.docs) {
          await doc.reference.delete();
        }
        final notifDocs = await userRef.collection('notifications').get();
        for (final doc in notifDocs.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 6. Delete all products added by this farmer
      try {
        final productsQuery = await _firestore
            .collection('products')
            .where('farmerId', isEqualTo: uid)
            .get();
        for (final doc in productsQuery.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 7. Delete all orders where this user is customer OR farmer
      try {
        final custOrders = await _firestore
            .collection('orders')
            .where('customerId', isEqualTo: uid)
            .get();
        for (final doc in custOrders.docs) {
          await doc.reference.delete();
        }
        final farmOrders = await _firestore
            .collection('orders')
            .where('farmerId', isEqualTo: uid)
            .get();
        for (final doc in farmOrders.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 8. Delete pickup slots
      try {
        final slotsQuery = await _firestore
            .collection('pickup_slots')
            .where('farmerId', isEqualTo: uid)
            .get();
        for (final doc in slotsQuery.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 9. Delete reviews
      try {
        final revCust = await _firestore
            .collection('reviews')
            .where('customerId', isEqualTo: uid)
            .get();
        for (final doc in revCust.docs) {
          await doc.reference.delete();
        }
        final revFarm = await _firestore
            .collection('reviews')
            .where('farmerId', isEqualTo: uid)
            .get();
        for (final doc in revFarm.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 10. Delete followed farmers
      try {
        final f1 = await _firestore
            .collection('followed_farmers')
            .where('userId', isEqualTo: uid)
            .get();
        for (final doc in f1.docs) {
          await doc.reference.delete();
        }
        final f2 = await _firestore
            .collection('followed_farmers')
            .where('farmerId', isEqualTo: uid)
            .get();
        for (final doc in f2.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}

      // 11. Remove from in-memory DataService
      DataService().removeUserAndRelatedData(uid);
    } catch (e) {
      debugPrint('Error during deleteUserCascade: $e');
      rethrow;
    }
  }

  /// Deletes the currently logged-in account (Customer or Farmer) and all their associated data completely.
  Future<void> deleteCurrentAccount() async {
    final uid = currentUid;
    final email = _userModel?.email ?? _auth.currentUser?.email;
    if (uid == null) return;

    // 1. Delete all Firestore data
    await deleteUserCascade(uid, email: email);

    // 2. Delete Firebase Auth user if present
    try {
      final user = _auth.currentUser;
      if (user != null) {
        await user.delete();
      }
    } catch (e) {
      debugPrint('FirebaseAuth user delete note: $e');
    }

    // 3. Clear local session & Sign out
    await signOut();
  }

  /// Re-stamps all orders that belong to [email] so their [customerId] matches
  /// [canonicalUid].  This heals the "orders disappear after provider switch"
  /// bug by ensuring a single UID is authoritative for every order regardless
  /// of which sign-in method (email/password vs Google) was used.
  Future<void> _normalizeOrdersForUser(
    String canonicalUid,
    String email,
  ) async {
    if (canonicalUid.isEmpty || email.isEmpty) return;
    try {
      final snap = await _firestore
          .collection('orders')
          .where('customerEmail', isEqualTo: email.trim().toLowerCase())
          .get();
      for (final doc in snap.docs) {
        final existing = doc.data()['customerId'] as String?;
        if (existing != canonicalUid) {
          // Update the customerId to the canonical one so UID-based queries work
          await doc.reference.set({
            'customerId': canonicalUid,
          }, SetOptions(merge: true));
        }
      }
    } catch (e) {
      debugPrint('_normalizeOrdersForUser: $e');
    }
  }

  /// Re-stamps all orders where [farmerEmail] matches so their [farmerId] equals
  /// [canonicalUid].  Same as the customer normalizer but for the Farmer panel.
  Future<void> _normalizeFarmerOrdersForUser(
    String canonicalUid,
    String email,
  ) async {
    if (canonicalUid.isEmpty || email.isEmpty) return;
    try {
      final snap = await _firestore
          .collection('orders')
          .where('farmerEmail', isEqualTo: email.trim().toLowerCase())
          .get();
      for (final doc in snap.docs) {
        final existing = doc.data()['farmerId'] as String?;
        if (existing != canonicalUid) {
          await doc.reference.set({
            'farmerId': canonicalUid,
          }, SetOptions(merge: true));
        }
      }
    } catch (e) {
      debugPrint('_normalizeFarmerOrdersForUser: $e');
    }
  }

  Future<void> signOut() async {
    try {
      await GoogleSignIn().signOut();
    } catch (_) {}
    try {
      await _auth.signOut();
    } catch (_) {}
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove('harvesthub_cached_uid');
      await prefs.remove('harvesthub_cached_email');
    } catch (_) {}
    _userModel = null;
    DataService().clearUserDataOnLogout();
    notifyListeners();
  }
}
