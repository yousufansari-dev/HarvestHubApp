import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../../theme/app_theme.dart';
import '../../services/auth_service.dart';

class AdminCustomersScreen extends StatefulWidget {
  const AdminCustomersScreen({super.key});

  @override
  State<AdminCustomersScreen> createState() => _AdminCustomersScreenState();
}

class _AdminCustomersScreenState extends State<AdminCustomersScreen> {
  final AuthService _auth = AuthService();
  List<Map<String, dynamic>> _customers = [];
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _loadCustomers();
  }

  Future<void> _loadCustomers() async {
    setState(() => _loading = true);
    final snapshot = await FirebaseFirestore.instance
        .collection('users')
        .where('role', isEqualTo: 'Customer')
        .get();
    if (!mounted) return;
    setState(() {
      _customers = snapshot.docs.map((doc) {
        final data = doc.data();
        return {
          'id': doc.id,
          'name': data['fullName'] as String? ?? 'Customer',
          'email': data['email'] as String? ?? '',
          'phone': data['phone'] as String? ?? '',
        };
      }).toList();
      _loading = false;
    });
  }

  Future<void> _deleteCustomer(Map<String, dynamic> c) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF15281E),
        title: Text(
          'Delete Customer?',
          style: GoogleFonts.playfairDisplay(
            color: const Color(0xFFF0F5F1),
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Text(
          'This will permanently delete ${c['name']}\'s profile, orders, wishlist, cart, reviews, and rewards data. This cannot be undone.',
          style: GoogleFonts.inter(
            color: const Color(0xFF8EAA95),
            fontSize: 13,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel', style: TextStyle(color: Color(0xFF88AB75))),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFD9534F),
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            child: const Text('Delete Permanently'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        await _auth.deleteUserCascade(c['id'] as String, email: c['email'] as String?);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Customer and all related data deleted successfully.'),
              backgroundColor: Color(0xFF1E3827),
            ),
          );
          _loadCustomers();
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Delete failed: $e'),
              backgroundColor: AppTheme.error,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        automaticallyImplyLeading: false,
        title: Text(
          'Customer Management',
          style: GoogleFonts.poppins(fontWeight: FontWeight.w600),
        ),
      ),
      body: SafeArea(
        bottom: true,
        child: _customers.isEmpty
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: const Color(0xFF15281E),
                      shape: BoxShape.circle,
                      border: Border.all(color: Colors.white.withAlpha(20)),
                    ),
                    child: const Icon(
                      Icons.people_outline_rounded,
                      size: 48,
                      color: AppTheme.primary,
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No Customers Found',
                    style: GoogleFonts.poppins(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFFF0F5F1),
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Customer accounts will appear here once registered.',
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: const Color(0xFF8FA497),
                    ),
                  ),
                ],
              ),
            )
          : ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: _customers.length,
              separatorBuilder: (context, index) => const SizedBox(height: 12),
              itemBuilder: (context, index) {
                final c = _customers[index];
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFF15281E),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: Colors.white.withAlpha(20)),
                  ),
                  child: Row(
                    children: [
                      CircleAvatar(
                        backgroundColor: const Color(0xFF1E3A2B),
                        child: Text(
                          (c['name'] as String).isNotEmpty
                              ? c['name'][0].toUpperCase()
                              : 'C',
                          style: GoogleFonts.poppins(
                            fontWeight: FontWeight.bold,
                            color: const Color(0xFFA1C68A),
                          ),
                        ),
                      ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              c['name'],
                              style: GoogleFonts.poppins(
                                fontSize: 15,
                                fontWeight: FontWeight.bold,
                                color: const Color(0xFFF0F5F1),
                              ),
                            ),
                            Text(
                              c['email'],
                              style: GoogleFonts.inter(
                                fontSize: 12,
                                color: const Color(0xFF8FA497),
                              ),
                            ),
                            if ((c['phone'] as String).isNotEmpty) ...[
                              const SizedBox(height: 4),
                              Text(
                                c['phone'],
                                style: GoogleFonts.inter(
                                  fontSize: 12,
                                  color: const Color(0xFF8FA497),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: const Color(0xFF1E3A2B),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: const Color(0xFFA1C68A).withAlpha(50),
                          ),
                        ),
                        child: Text(
                          'Active',
                          style: GoogleFonts.poppins(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: const Color(0xFFA1C68A),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      IconButton(
                        icon: const Icon(Icons.delete_outline_rounded, color: Color(0xFFE63946), size: 20),
                        tooltip: 'Delete Customer',
                        onPressed: () => _deleteCustomer(c),
                      ),
                    ],
                  ),
                );
              },
            ),
      ),
    );
  }
}
