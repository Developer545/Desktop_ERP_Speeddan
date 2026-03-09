// ══════════════════════════════════════════════════════════
// ROUTES — Autenticación del panel admin
// ══════════════════════════════════════════════════════════

const express    = require('express')
const bcrypt     = require('bcryptjs')
const jwt        = require('jsonwebtoken')
const rateLimit  = require('express-rate-limit')
const pool       = require('../db')
const { requireAuth }             = require('../middleware/auth.middleware')
const { sanitizeStr }             = require('../utils/validators')

const router = express.Router()

// Rate limit específico para login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de login. Intenta de nuevo en 15 minutos.' },
})

// ── POST /api/auth/login ───────────────────────────────────
router.post('/login', loginLimiter, async (req, res) => {
  const username = sanitizeStr(req.body.username, 50)
  const password = sanitizeStr(req.body.password, 128)

  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM admin_users WHERE username = $1',
      [username]
    )
    const user = rows[0]
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' })

    const isMatch = await bcrypt.compare(password, user.password_hash)
    if (!isMatch) return res.status(401).json({ error: 'Credenciales inválidas' })

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    )

    const isProduction = process.env.NODE_ENV === 'production' || !!process.env.VERCEL

    res.cookie('admin_token', token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 8 * 60 * 60 * 1000,
    })

    res.json({ success: true, username: user.username })
  } catch (err) {
    console.error('[auth/login]', err.message)
    res.status(500).json({ error: 'Error interno del servidor' })
  }
})

// ── POST /api/auth/logout ──────────────────────────────────
router.post('/logout', (_req, res) => {
  res.clearCookie('admin_token')
  res.json({ success: true })
})

// ── GET /api/auth/check ────────────────────────────────────
router.get('/check', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user })
})

// ── POST /api/auth/change-password ────────────────────────
router.post('/change-password', requireAuth, async (req, res) => {
  const currentPassword = sanitizeStr(req.body.currentPassword, 128)
  const newPassword     = sanitizeStr(req.body.newPassword, 128)

  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Contraseña actual y nueva son requeridas' })

  // Validaciones de fortaleza
  if (newPassword.length < 8)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' })
  if (!/[A-Z]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos una mayúscula' })
  if (!/[a-z]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos una minúscula' })
  if (!/[0-9]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos un número' })
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos un carácter especial' })

  try {
    const { rows } = await pool.query('SELECT * FROM admin_users WHERE id = $1', [req.user.id])
    const user = rows[0]
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' })

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash)
    if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta' })

    const newHash = await bcrypt.hash(newPassword, 12)
    await pool.query('UPDATE admin_users SET password_hash = $1 WHERE id = $2', [newHash, user.id])

    res.json({ success: true, message: 'Contraseña actualizada correctamente' })
  } catch (err) {
    console.error('[auth/change-password]', err.message)
    res.status(500).json({ error: 'Error al cambiar la contraseña' })
  }
})

module.exports = router
