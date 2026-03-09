// ══════════════════════════════════════════════════════════
// ROUTES — Gestión de licencias desktop
// ══════════════════════════════════════════════════════════

const express = require('express')
const crypto  = require('crypto')
const pool    = require('../db')
const { requireAuth }                           = require('../middleware/auth.middleware')
const { sanitizeStr, sanitizeInt, addDays, isAfter } = require('../utils/validators')

const router = express.Router()

// ── GET /api/licenses/stats ────────────────────────────────
router.get('/stats', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)                                                          AS total,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date > NOW())                                  AS activas,
        COUNT(*) FILTER (WHERE is_active = false)                         AS pendientes,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date <= NOW())                                  AS expiradas,
        COUNT(*) FILTER (WHERE is_active = true
            AND expiration_date > NOW()
            AND expiration_date <= NOW() + INTERVAL '5 days')             AS vencen_pronto
      FROM licenses
      WHERE deleted_at IS NULL
    `)
    res.json(rows[0])
  } catch (err) {
    console.error('[licenses/stats]', err.message)
    res.status(500).json({ error: 'Error al obtener estadísticas' })
  }
})

// ── GET /api/licenses ──────────────────────────────────────
router.get('/', requireAuth, async (_req, res) => {
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

// ── POST /api/licenses/generate ───────────────────────────
router.post('/generate', requireAuth, async (req, res) => {
  const duration_days     = sanitizeInt(req.body.duration_days)
  const client_name       = sanitizeStr(req.body.client_name)
  const client_email      = sanitizeStr(req.body.client_email)
  const client_phone      = sanitizeStr(req.body.client_phone, 30)
  const initial_username  = sanitizeStr(req.body.initial_username, 50)
  const initial_password  = sanitizeStr(req.body.initial_password, 128)
  const database_url      = sanitizeStr(req.body.database_url, 500)
  const empresa_nombre    = sanitizeStr(req.body.empresa_nombre)
  const empresa_nit       = sanitizeStr(req.body.empresa_nit, 20)
  const plan              = sanitizeStr(req.body.plan, 30) || 'basico'
  const max_users         = sanitizeInt(req.body.max_users, 1, 100) || 3

  if (!duration_days)
    return res.status(400).json({ error: 'Especifica una cantidad de días válida (1-36500).' })

  const raw = crypto.randomUUID().replace(/-/g, '').toUpperCase()
  const license_key = `SPEED-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`

  try {
    const { rows } = await pool.query(
      `INSERT INTO licenses
         (license_key, duration_days, client_name, client_email, client_phone,
          initial_username, initial_password, database_url, empresa_nombre,
          empresa_nit, plan, max_users)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [license_key, duration_days, client_name, client_email, client_phone,
       initial_username, initial_password, database_url, empresa_nombre,
       empresa_nit, plan, max_users]
    )
    res.status(201).json({ success: true, data: rows[0] })
  } catch (err) {
    console.error('[licenses/generate]', err.message)
    res.status(500).json({ error: 'Error al generar licencia' })
  }
})

// ── PATCH /api/licenses/:id/extend ────────────────────────
router.patch('/:id/extend', requireAuth, async (req, res) => {
  const extra_days = sanitizeInt(req.body.extra_days)
  const id         = sanitizeInt(req.params.id, 1, 2147483647)

  if (!extra_days) return res.status(400).json({ error: 'Especifica días adicionales válidos (1-36500).' })
  if (!id)         return res.status(400).json({ error: 'ID de licencia inválido.' })

  try {
    const { rows } = await pool.query(
      'SELECT * FROM licenses WHERE id = $1 AND deleted_at IS NULL', [id]
    )
    const lic = rows[0]
    if (!lic) return res.status(404).json({ error: 'Licencia no encontrada.' })

    if (lic.expiration_date) {
      const base = new Date(lic.expiration_date) > new Date()
        ? new Date(lic.expiration_date)
        : new Date()
      const newExp = addDays(base, extra_days)
      await pool.query(
        `UPDATE licenses
         SET expiration_date = $1, duration_days = duration_days + $2, is_active = true
         WHERE id = $3`,
        [newExp.toISOString(), extra_days, lic.id]
      )
    } else {
      await pool.query(
        'UPDATE licenses SET duration_days = duration_days + $1 WHERE id = $2',
        [extra_days, lic.id]
      )
    }

    const { rows: updated } = await pool.query('SELECT * FROM licenses WHERE id = $1', [id])
    res.json({ success: true, data: updated[0] })
  } catch (err) {
    console.error('[licenses/extend]', err.message)
    res.status(500).json({ error: 'Error al extender licencia' })
  }
})

// ── DELETE /api/licenses/:id (soft delete) ────────────────
router.delete('/:id', requireAuth, async (req, res) => {
  const id = sanitizeInt(req.params.id, 1, 2147483647)
  if (!id) return res.status(400).json({ error: 'ID de licencia inválido.' })

  try {
    const { rowCount } = await pool.query(
      'UPDATE licenses SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL', [id]
    )
    if (rowCount === 0)
      return res.status(404).json({ error: 'Licencia no encontrada.' })

    res.json({ success: true, message: 'Licencia revocada correctamente' })
  } catch (err) {
    console.error('[licenses/delete]', err.message)
    res.status(500).json({ error: 'Error al revocar licencia' })
  }
})

// ── POST /api/licenses/activate (público — consumido por Electron) ──
router.post('/activate', async (req, res) => {
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
        if (isAfter(new Date(), new Date(row.expiration_date)))
          return res.status(403).json({ error: 'Tu periodo de prueba ha expirado.' })

        return res.json({
          success: true,
          message: 'Licencia re-validada en esta computadora.',
          expiration_date:  row.expiration_date,
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
      expiration_date:  expirationDate.toISOString(),
      initial_username: row.initial_username || null,
      initial_password: row.initial_password || null,
    })
  } catch (err) {
    console.error('[licenses/activate]', err.message)
    res.status(500).json({ error: 'Error interno del servidor' })
  }
})

// ── POST /api/licenses/resolve (público — consulta DB del tenant) ──
router.post('/resolve', async (req, res) => {
  const license_key = sanitizeStr(req.body.license_key, 20)
  if (!license_key)
    return res.status(400).json({ error: 'license_key es requerido' })

  try {
    const { rows } = await pool.query(
      `SELECT license_key, database_url, empresa_nombre, empresa_nit,
              plan, max_users, is_active, expiration_date
       FROM licenses
       WHERE license_key = $1 AND deleted_at IS NULL`,
      [license_key]
    )
    const lic = rows[0]
    if (!lic)
      return res.status(404).json({ error: 'Licencia no encontrada' })
    if (!lic.is_active)
      return res.status(403).json({ error: 'Licencia no activada' })
    if (lic.expiration_date && isAfter(new Date(), new Date(lic.expiration_date)))
      return res.status(403).json({ error: 'Licencia expirada' })
    if (!lic.database_url)
      return res.status(404).json({ error: 'Licencia sin base de datos configurada. Contacte al administrador.' })

    res.json({
      success: true,
      database_url:    lic.database_url,
      empresa_nombre:  lic.empresa_nombre,
      empresa_nit:     lic.empresa_nit,
      plan:            lic.plan,
      max_users:       lic.max_users,
    })
  } catch (err) {
    console.error('[licenses/resolve]', err.message)
    res.status(500).json({ error: 'Error interno del servidor' })
  }
})

module.exports = router
