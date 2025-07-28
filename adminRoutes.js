import express from 'express';
import {
  authenticateToken,
  requireGGPTAccess
} from './auth.js';
import { db } from './db.js';

const router = express.Router();

// Helper to analyse GGPT specific LDAP groups and derive access level & user type
function analyzeGGPTGroups(ldapGroups = []) {
  const gGptPrefix = 'g-gpt';
  const gGptGroups = ldapGroups.filter((g) => g.startsWith(gGptPrefix));

  let accessLevel = 'none';
  let userType = 'standard';

  if (gGptGroups.includes('g-gpt-admins')) {
    accessLevel = 'admin';
    userType = 'internal';
  } else if (gGptGroups.includes('g-gpt-internal')) {
    accessLevel = 'internal';
    userType = 'internal';
  } else if (gGptGroups.includes('g-gpt-external')) {
    accessLevel = 'external';
    userType = 'external';
  }

  return { gGptGroups, accessLevel, userType };
}

// ==========================================
// ADMIN USER MANAGEMENT
// ==========================================

// GET /admin/users – fetch all users enriched with LDAP & GGPT metadata
router.get(
  '/users',
  authenticateToken,
  requireGGPTAccess('admin_panel'),
  async (req, res) => {
    try {
      /* eslint-disable sonarjs/no-duplicate-string */
      const [users] = await db.query(
        `SELECT u.id,
                u.name,
                u.email,
                u.ldap_username,
                u.account_status,
                u.last_login,
                GROUP_CONCAT(DISTINCT r.name)               AS roles,
                li.ldap_groups,
                li.department,
                li.title
         FROM users u
                  LEFT JOIN user_roles ur ON u.id = ur.user_id
                  LEFT JOIN roles r ON ur.role_id = r.id
                  LEFT JOIN ldap_user_info li ON u.id = li.user_id
         GROUP BY u.id`);

      const enhancedUsers = users.map((user) => {
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
  }
);

// PUT /admin/users/:id – update user basic profile (department, title, account status)
router.put(
  '/users/:id',
  authenticateToken,
  requireGGPTAccess('admin_panel'),
  async (req, res) => {
    const { id } = req.params;
    const { department, title, account_status } = req.body;

    if (!department && !title && !account_status) {
      return res.status(400).json({ error: 'Güncellenecek alan verilmedi.' });
    }

    const fields = [];
    const values = [];

    if (department !== undefined) {
      fields.push('department = ?');
      values.push(department);
    }

    if (title !== undefined) {
      fields.push('title = ?');
      values.push(title);
    }

    if (account_status !== undefined) {
      fields.push('account_status = ?');
      values.push(account_status);
    }

    values.push(id);

    try {
      await db.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values);
      res.json({ success: true });
    } catch (error) {
      console.error('Kullanıcı güncelleme hatası:', error);
      res.status(500).json({ error: 'Kullanıcı güncellenemedi' });
    }
  }
);

export default router;