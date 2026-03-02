// ══════════════════════════════════════════════════════════
// SERVIDOR DE LICENCIAS — Speeddansys ERP
// Express + PostgreSQL (compatible Neon + Vercel)
// ══════════════════════════════════════════════════════════

const path = require('path')
require('dotenv').config({ path: path.resolve(__dirname, '.env') })
const express = require('express')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
const crypto = require('crypto')

// Helpers de fecha (reemplazan date-fns para compatibilidad CommonJS en Vercel)
function addDays(date, days) {
  const result = new Date(date)
  result.setDate(result.getDate() + days)
  return result
}
function isAfter(dateA, dateB) {
  return new Date(dateA) > new Date(dateB)
}
const bcrypt = require('bcryptjs')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const pool = require('./db')

// ── Configuración ─────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET no está definido. Configúralo en .env o variables de entorno.')
  if (!process.env.VERCEL) process.exit(1)
}

const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:4000']

// ── App Express ───────────────────────────────────────────
const app = express()

app.use(cors({
  origin: (origin, cb) => {
    // Permitir requests sin origin (Postman, Electron, curl, same-origin)
    if (!origin) return cb(null, true)
    // Permitir localhost y 127.0.0.1 en cualquier puerto (mismo servidor)
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true)
    if (CORS_ORIGINS.includes(origin)) return cb(null, true)
    return cb(new Error('Origen no permitido por CORS'))
  },
  credentials: true,
}))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

// ── Rate Limiting ─────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' },
})
app.use('/api/', globalLimiter)

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de login. Intenta de nuevo en 15 minutos.' },
})

// ── Helpers de validación ─────────────────────────────────
function sanitizeStr(val, maxLen = 255) {
  if (typeof val !== 'string') return null
  return val.trim().slice(0, maxLen) || null
}

function sanitizeInt(val, min = 1, max = 36500) {
  const n = parseInt(val)
  if (isNaN(n) || n < min || n > max) return null
  return n
}

// ══════════════════════════════════════════════════════════
// MIDDLEWARE DE AUTENTICACIÓN
// ══════════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  const token = req.cookies.admin_token || req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'No autorizado' })
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' })
  }
}

// ══════════════════════════════════════════════════════════
// AUTENTICACIÓN
// ══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const username = sanitizeStr(req.body.username, 50)
  const password = sanitizeStr(req.body.password, 128)

  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM admin_users WHERE username = $1', [username]
    )
    const user = rows[0]
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' })

    const isMatch = await bcrypt.compare(password, user.password_hash)
    if (!isMatch) return res.status(401).json({ error: 'Credenciales inválidas' })

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
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

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('admin_token')
  res.json({ success: true })
})

app.get('/api/auth/check', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user })
})

// ══════════════════════════════════════════════════════════
// CAMBIAR CONTRASEÑA
// ══════════════════════════════════════════════════════════
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const currentPassword = sanitizeStr(req.body.currentPassword, 128)
  const newPassword = sanitizeStr(req.body.newPassword, 128)

  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Contraseña actual y nueva son requeridas' })

  // Validar fortaleza de la nueva contraseña
  if (newPassword.length < 8)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' })
  if (!/[A-Z]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos una mayúscula' })
  if (!/[a-z]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos una minúscula' })
  if (!/[0-9]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos un número' })
  if (!/[!@#$%^&*()_+\-=[\]{};':"|,.<>/?]/.test(newPassword))
    return res.status(400).json({ error: 'La contraseña debe incluir al menos un carácter especial' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM admin_users WHERE id = $1', [req.user.id]
    )
    const user = rows[0]
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' })

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash)
    if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta' })

    const newHash = await bcrypt.hash(newPassword, 12)
    await pool.query(
      'UPDATE admin_users SET password_hash = $1 WHERE id = $2',
      [newHash, user.id]
    )

    res.json({ success: true, message: 'Contraseña actualizada correctamente' })
  } catch (err) {
    console.error('[auth/change-password]', err.message)
    res.status(500).json({ error: 'Error al cambiar la contraseña' })
  }
})

// ══════════════════════════════════════════════════════════
// ESTADÍSTICAS DEL DASHBOARD
// ══════════════════════════════════════════════════════════
app.get('/api/licenses/stats', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)                                                        AS total,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date > NOW())                                AS activas,
        COUNT(*) FILTER (WHERE is_active = false)                       AS pendientes,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date <= NOW())                               AS expiradas,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date > NOW()
            AND expiration_date <= NOW() + INTERVAL '5 days')           AS vencen_pronto
      FROM licenses
      WHERE deleted_at IS NULL
    `)
    res.json(rows[0])
  } catch (err) {
    console.error('[licenses/stats]', err.message)
    res.status(500).json({ error: 'Error al obtener estadísticas' })
  }
})

// ══════════════════════════════════════════════════════════
// LISTAR LICENCIAS
// ══════════════════════════════════════════════════════════
app.get('/api/licenses', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM licenses WHERE deleted_at IS NULL ORDER BY created_at DESC'
    )
    res.json(rows)
  } catch (err) {
    console.error('[licenses/list]', err.message)
    res.status(500).json({ error: 'Error al listar licencias' })
  }
})

// ══════════════════════════════════════════════════════════
// GENERAR NUEVA LICENCIA
// ══════════════════════════════════════════════════════════
app.post('/api/licenses/generate', requireAuth, async (req, res) => {
  const duration_days = sanitizeInt(req.body.duration_days)
  const client_name = sanitizeStr(req.body.client_name)
  const client_email = sanitizeStr(req.body.client_email)
  const client_phone = sanitizeStr(req.body.client_phone, 30)
  const initial_username = sanitizeStr(req.body.initial_username, 50)
  const initial_password = sanitizeStr(req.body.initial_password, 128)

  if (!duration_days)
    return res.status(400).json({ error: 'Especifica una cantidad de días válida (1-36500).' })

  const raw = crypto.randomUUID().replace(/-/g, '').toUpperCase()
  const license_key = `SPEED-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`

  try {
    const { rows } = await pool.query(
      `INSERT INTO licenses (license_key, duration_days, client_name, client_email, client_phone, initial_username, initial_password)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [license_key, duration_days, client_name, client_email, client_phone,
       initial_username, initial_password]
    )
    res.status(201).json({ success: true, data: rows[0] })
  } catch (err) {
    console.error('[licenses/generate]', err.message)
    res.status(500).json({ error: 'Error al generar licencia' })
  }
})

// ══════════════════════════════════════════════════════════
// EXTENDER LICENCIA (sumar días)
// ══════════════════════════════════════════════════════════
app.patch('/api/licenses/:id/extend', requireAuth, async (req, res) => {
  const extra_days = sanitizeInt(req.body.extra_days)
  const id = sanitizeInt(req.params.id, 1, 2147483647)

  if (!extra_days)
    return res.status(400).json({ error: 'Especifica días adicionales válidos (1-36500).' })
  if (!id)
    return res.status(400).json({ error: 'ID de licencia inválido.' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM licenses WHERE id = $1 AND deleted_at IS NULL', [id]
    )
    const lic = rows[0]
    if (!lic) return res.status(404).json({ error: 'Licencia no encontrada.' })

    if (lic.expiration_date) {
      // Ya activada: extender desde la fecha de vencimiento actual
      // Si ya expiró, extender desde hoy para "revivir" la demo
      const base = new Date(lic.expiration_date) > new Date()
        ? new Date(lic.expiration_date)
        : new Date()
      const newExp = addDays(base, extra_days)

      await pool.query(
        `UPDATE licenses
         SET expiration_date = $1,
             duration_days   = duration_days + $2,
             is_active       = true
         WHERE id = $3`,
        [newExp.toISOString(), extra_days, lic.id]
      )
    } else {
      // Aún no activada: solo sumar días al plazo
      await pool.query(
        'UPDATE licenses SET duration_days = duration_days + $1 WHERE id = $2',
        [extra_days, lic.id]
      )
    }

    const { rows: updated } = await pool.query(
      'SELECT * FROM licenses WHERE id = $1', [id]
    )
    res.json({ success: true, data: updated[0] })
  } catch (err) {
    console.error('[licenses/extend]', err.message)
    res.status(500).json({ error: 'Error al extender licencia' })
  }
})

// ══════════════════════════════════════════════════════════
// REVOCAR LICENCIA (soft delete)
// ══════════════════════════════════════════════════════════
app.delete('/api/licenses/:id', requireAuth, async (req, res) => {
  const id = sanitizeInt(req.params.id, 1, 2147483647)
  if (!id) return res.status(400).json({ error: 'ID de licencia inválido.' })

  try {
    const { rowCount } = await pool.query(
      'UPDATE licenses SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL',
      [id]
    )
    if (rowCount === 0)
      return res.status(404).json({ error: 'Licencia no encontrada.' })

    res.json({ success: true, message: 'Licencia revocada correctamente' })
  } catch (err) {
    console.error('[licenses/delete]', err.message)
    res.status(500).json({ error: 'Error al revocar licencia' })
  }
})

// ══════════════════════════════════════════════════════════
// ACTIVACIÓN (consumido por el .exe Electron y la versión web)
// ══════════════════════════════════════════════════════════
app.post('/api/licenses/activate', async (req, res) => {
  const license_key = sanitizeStr(req.body.license_key, 20)
  const hardware_id = sanitizeStr(req.body.hardware_id, 128)

  if (!license_key || !hardware_id)
    return res.status(400).json({ error: 'license_key y hardware_id son requeridos' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM licenses WHERE license_key = $1 AND deleted_at IS NULL',
      [license_key]
    )
    const row = rows[0]

    if (!row)
      return res.status(404).json({ error: 'La licencia ingresada no existe.' })

    if (row.is_active || row.hardware_id) {
      if (row.hardware_id === hardware_id) {
        if (isAfter(new Date(), new Date(row.expiration_date))) {
          return res.status(403).json({ error: 'Tu periodo de prueba ha expirado.' })
        }
        return res.json({
          success: true,
          message: 'Licencia re-validada en esta computadora.',
          expiration_date: row.expiration_date,
          initial_username: row.initial_username || null,
          initial_password: row.initial_password || null,
        })
      }
      return res.status(403).json({
        error: 'Esta licencia ya fue activada en otra computadora. Acceso denegado.',
      })
    }

    const expirationDate = addDays(new Date(), row.duration_days)
    await pool.query(
      'UPDATE licenses SET hardware_id = $1, is_active = true, expiration_date = $2 WHERE id = $3',
      [hardware_id, expirationDate.toISOString(), row.id]
    )

    res.json({
      success: true,
      message: '¡Licencia activada con éxito!',
      expiration_date: expirationDate.toISOString(),
      initial_username: row.initial_username || null,
      initial_password: row.initial_password || null,
    })
  } catch (err) {
    console.error('[licenses/activate]', err.message)
    res.status(500).json({ error: 'Error interno del servidor' })
  }
})

// ══════════════════════════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════════════════════════
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ status: 'ok', timestamp: new Date().toISOString() })
  } catch {
    res.status(503).json({ status: 'error', message: 'Base de datos no disponible' })
  }
})

// ══════════════════════════════════════════════════════════
// INICIAR SERVIDOR (solo cuando NO es Vercel)
// ══════════════════════════════════════════════════════════
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 4000
  app.listen(PORT, () => {
    console.log(`🚀 License Server corriendo en http://localhost:${PORT}`)
  })
}

// Exportar para Vercel serverless
module.exports = app
