// ==========================================
// ADMIN ROUTES AND FUNCTIONS
// ==========================================

import express from 'express';
import { 
  authenticateToken, 
  isAdmin, 
  requireGGPTAccess 
} from './auth.js';
import { db } from './db.js';

const router = express.Router();

// Helper function to analyze GGPT groups
function analyzeGGPTGroups(ldapGroups) {
  const gGptGroups = ldapGroups.filter(group => 
    group.toLowerCase().includes('ggpt') || 
    group.toLowerCase().includes('generative') ||
    group.toLowerCase().includes('ai')
  );
  
  let accessLevel = 'none';
  let userType = 'standard';
  
  if (gGptGroups.some(group => group.toLowerCase().includes('admin'))) {
    accessLevel = 'admin';
    userType = 'admin';
  } else if (gGptGroups.some(group => group.toLowerCase().includes('power'))) {
    accessLevel = 'power';
    userType = 'power_user';
  } else if (gGptGroups.length > 0) {
    accessLevel = 'basic';
    userType = 'user';
  }
  
  return {
    gGptGroups,
    accessLevel,
    userType
  };
}

// ==========================================
// ADMIN USER MANAGEMENT
// ==========================================

router.get('/users', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const [users] = await db.query(`
      SELECT u.id, u.name, u.email, u.ldap_username, u.account_status, u.last_login,
             GROUP_CONCAT(r.name) as roles,
             li.ldap_groups, li.department, li.title
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      LEFT JOIN ldap_user_info li ON u.id = li.user_id
      GROUP BY u.id
      ORDER BY u.name
    `);

    const enhancedUsers = users.map(user => {
      const ldapGroups = user.ldap_groups ? user.ldap_groups.split(',') : [];
      const gGptAnalysis = analyzeGGPTGroups(ldapGroups);
      
      return {
        id: user.id,
        name: user.name,
        email: user.email,
        isLDAPUser: !!user.ldap_username,
        account_status: user.account_status,
        last_login: user.last_login,
        roles: user.roles ? user.roles.split(',') : [],
        department: user.department,
        title: user.title,
        gGptGroups: gGptAnalysis.gGptGroups,
        accessLevel: gGptAnalysis.accessLevel,
        userType: gGptAnalysis.userType
      };
    });

    res.json(enhancedUsers);
  } catch (error) {
    console.error('Kullanıcı listeleme hatası:', error);
    res.status(500).json({ error: 'Kullanıcılar listelenemedi' });
  }
});

// Get specific user details
router.get('/users/:id', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const userId = req.params.id;
    const [users] = await db.query(`
      SELECT u.*, li.ldap_groups, li.department, li.title, li.manager,
             GROUP_CONCAT(r.name) as roles
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      LEFT JOIN ldap_user_info li ON u.id = li.user_id
      WHERE u.id = ?
      GROUP BY u.id
    `, [userId]);

    if (users.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const user = users[0];
    const ldapGroups = user.ldap_groups ? user.ldap_groups.split(',') : [];
    const gGptAnalysis = analyzeGGPTGroups(ldapGroups);

    const enhancedUser = {
      ...user,
      roles: user.roles ? user.roles.split(',') : [],
      gGptGroups: gGptAnalysis.gGptGroups,
      accessLevel: gGptAnalysis.accessLevel,
      userType: gGptAnalysis.userType
    };

    res.json(enhancedUser);
  } catch (error) {
    console.error('Kullanıcı detay hatası:', error);
    res.status(500).json({ error: 'Kullanıcı detayları alınamadı' });
  }
});

// Update user status
router.patch('/users/:id/status', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { status } = req.body;

    if (!['active', 'inactive', 'suspended'].includes(status)) {
      return res.status(400).json({ error: 'Geçersiz durum değeri' });
    }

    await db.query(
      'UPDATE users SET account_status = ?, updated_at = NOW() WHERE id = ?',
      [status, userId]
    );

    res.json({ message: 'Kullanıcı durumu güncellendi', status });
  } catch (error) {
    console.error('Kullanıcı durum güncelleme hatası:', error);
    res.status(500).json({ error: 'Kullanıcı durumu güncellenemedi' });
  }
});

// Assign role to user
router.post('/users/:id/roles', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { roleId } = req.body;

    // Check if role exists
    const [roles] = await db.query('SELECT id FROM roles WHERE id = ?', [roleId]);
    if (roles.length === 0) {
      return res.status(404).json({ error: 'Rol bulunamadı' });
    }

    // Check if user already has this role
    const [existingRoles] = await db.query(
      'SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?',
      [userId, roleId]
    );

    if (existingRoles.length > 0) {
      return res.status(400).json({ error: 'Kullanıcı zaten bu role sahip' });
    }

    await db.query(
      'INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, NOW())',
      [userId, roleId]
    );

    res.json({ message: 'Rol başarıyla atandı' });
  } catch (error) {
    console.error('Rol atama hatası:', error);
    res.status(500).json({ error: 'Rol atanamadı' });
  }
});

// Remove role from user
router.delete('/users/:id/roles/:roleId', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const { id: userId, roleId } = req.params;

    const [result] = await db.query(
      'DELETE FROM user_roles WHERE user_id = ? AND role_id = ?',
      [userId, roleId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Kullanıcı rolü bulunamadı' });
    }

    res.json({ message: 'Rol başarıyla kaldırıldı' });
  } catch (error) {
    console.error('Rol kaldırma hatası:', error);
    res.status(500).json({ error: 'Rol kaldırılamadı' });
  }
});

// ==========================================
// ADMIN ROLE MANAGEMENT
// ==========================================

// Get all roles
router.get('/roles', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const [roles] = await db.query(`
      SELECT r.*, COUNT(ur.user_id) as user_count
      FROM roles r
      LEFT JOIN user_roles ur ON r.id = ur.role_id
      GROUP BY r.id
      ORDER BY r.name
    `);

    res.json(roles);
  } catch (error) {
    console.error('Rol listeleme hatası:', error);
    res.status(500).json({ error: 'Roller listelenemedi' });
  }
});

// Create new role
router.post('/roles', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const { name, description, permissions } = req.body;

    if (!name || !description) {
      return res.status(400).json({ error: 'Rol adı ve açıklama gerekli' });
    }

    const [result] = await db.query(
      'INSERT INTO roles (name, description, permissions, created_at) VALUES (?, ?, ?, NOW())',
      [name, description, JSON.stringify(permissions || [])]
    );

    res.status(201).json({ 
      message: 'Rol başarıyla oluşturuldu',
      roleId: result.insertId 
    });
  } catch (error) {
    console.error('Rol oluşturma hatası:', error);
    res.status(500).json({ error: 'Rol oluşturulamadı' });
  }
});

// ==========================================
// ADMIN ANALYTICS
// ==========================================

// Get system statistics
router.get('/stats', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const [userStats] = await db.query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN account_status = 'active' THEN 1 END) as active_users,
        COUNT(CASE WHEN ldap_username IS NOT NULL THEN 1 END) as ldap_users,
        COUNT(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as active_last_30_days
      FROM users
    `);

    const [roleStats] = await db.query(`
      SELECT COUNT(*) as total_roles FROM roles
    `);

    const [sessionStats] = await db.query(`
      SELECT 
        COUNT(*) as total_sessions,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as sessions_last_24h
      FROM user_sessions
    `);

    res.json({
      users: userStats[0],
      roles: roleStats[0],
      sessions: sessionStats[0]
    });
  } catch (error) {
    console.error('İstatistik alma hatası:', error);
    res.status(500).json({ error: 'İstatistikler alınamadı' });
  }
});

// Get user activity logs
router.get('/activity', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const { page = 1, limit = 50, userId, action } = req.query;
    const offset = (page - 1) * limit;

    let whereClause = '';
    const params = [];

    if (userId) {
      whereClause += ' WHERE al.user_id = ?';
      params.push(userId);
    }

    if (action) {
      whereClause += (whereClause ? ' AND' : ' WHERE') + ' al.action = ?';
      params.push(action);
    }

    const [activities] = await db.query(`
      SELECT al.*, u.name as user_name, u.email as user_email
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ${whereClause}
      ORDER BY al.created_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    const [countResult] = await db.query(`
      SELECT COUNT(*) as total
      FROM activity_logs al
      ${whereClause}
    `, params);

    res.json({
      activities,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        totalPages: Math.ceil(countResult[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Aktivite log hatası:', error);
    res.status(500).json({ error: 'Aktivite logları alınamadı' });
  }
});

// ==========================================
// ADMIN SYSTEM MANAGEMENT
// ==========================================

// Get system configuration
router.get('/config', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const [configs] = await db.query(`
      SELECT config_key, config_value, description, updated_at
      FROM system_config
      ORDER BY config_key
    `);

    res.json(configs);
  } catch (error) {
    console.error('Konfigürasyon alma hatası:', error);
    res.status(500).json({ error: 'Konfigürasyon alınamadı' });
  }
});

// Update system configuration
router.patch('/config/:key', authenticateToken, requireGGPTAccess('admin_panel'), async (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;

    await db.query(
      'UPDATE system_config SET config_value = ?, updated_at = NOW() WHERE config_key = ?',
      [value, key]
    );

    res.json({ message: 'Konfigürasyon güncellendi' });
  } catch (error) {
    console.error('Konfigürasyon güncelleme hatası:', error);
    res.status(500).json({ error: 'Konfigürasyon güncellenemedi' });
  }
});

export default router;