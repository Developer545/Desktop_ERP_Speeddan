// ══════════════════════════════════════════════════════════
// ROUTES — Gestión de empresas / suscripciones web
// ══════════════════════════════════════════════════════════

const express = require('express')
const pool = require('../db')
const { requireAuth } = require('../middleware/auth.middleware')
const { sanitizeStr, sanitizeInt, isValidEmail, isValidSubdominio, addDays } = require('../utils/validators')
const { sendWelcomeEmail } = require('../services/email.service')
const { provisionEmisor } = require('../services/erp.service')

const router = express.Router()

// ── Constantes de dominio ─────────────────────────────────
const PLANES_VALIDOS = ['emprendedor', 'empresarial', 'corporativo_cloud', 'corporativo_local']
const ESTADOS_VALIDOS = ['prueba', 'activa', 'suspendida', 'cancelada']

/** Módulos habilitados según el plan */
const MODULOS_POR_PLAN = {
  emprendedor: {
    facturacion: true, inventarios: true, clientes: true,
    proveedores: true, reportes: true,
    planilla: false, cxc: false, cxp: false, gastos: false,
    sucursales: false, multiusuario: false, analytics: false,
  },
  empresarial: {
    facturacion: true, inventarios: true, clientes: true,
    proveedores: true, reportes: true,
    planilla: true, cxc: true, cxp: true, gastos: true,
    sucursales: false, multiusuario: false, analytics: false,
  },
  corporativo_cloud: {
    facturacion: true, inventarios: true, clientes: true,
    proveedores: true, reportes: true,
    planilla: true, cxc: true, cxp: true, gastos: true,
    sucursales: true, multiusuario: true, analytics: true,
  },
  corporativo_local: {
    facturacion: true, inventarios: true, clientes: true,
    proveedores: true, reportes: true,
    planilla: true, cxc: true, cxp: true, gastos: true,
    sucursales: true, multiusuario: true, analytics: true,
  },
}

/** Límite de usuarios por plan */
const MAX_USUARIOS_POR_PLAN = {
  emprendedor: 3,
  empresarial: 10,
  corporativo_cloud: 50,
  corporativo_local: 20,
}

// ══════════════════════════════════════════════════════════
// GET /api/empresas/stats — KPIs del dashboard
// ══════════════════════════════════════════════════════════
router.get('/stats', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)                                                                AS total,
        COUNT(*) FILTER (WHERE estado = 'prueba')                              AS en_prueba,
        COUNT(*) FILTER (WHERE estado = 'activa')                              AS activas,
        COUNT(*) FILTER (WHERE estado = 'suspendida')                          AS suspendidas,
        COUNT(*) FILTER (WHERE estado = 'cancelada')                           AS canceladas,
        COUNT(*) FILTER (
          WHERE estado = 'activa'
            AND fecha_vencimiento IS NOT NULL
            AND fecha_vencimiento > NOW()
            AND fecha_vencimiento <= NOW() + INTERVAL '5 days'
        )                                                                       AS vencen_pronto
      FROM empresas
      WHERE deleted_at IS NULL
    `)
    res.json(rows[0])
  } catch (err) {
    console.error('[empresas/stats]', err.message)
    res.status(500).json({ error: 'Error al obtener estadísticas' })
  }
})

// ══════════════════════════════════════════════════════════
// GET /api/empresas — Listar todas
// ══════════════════════════════════════════════════════════
router.get('/', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM empresas WHERE deleted_at IS NULL ORDER BY created_at DESC'
    )
    res.json(rows)
  } catch (err) {
    console.error('[empresas/list]', err.message)
    res.status(500).json({ error: 'Error al listar empresas' })
  }
})

// ══════════════════════════════════════════════════════════
// POST /api/empresas — Crear empresa + provisionar ERP + email
// ══════════════════════════════════════════════════════════
router.post('/', requireAuth, async (req, res) => {
  // ── Extraer y sanitizar campos ───────────────────────────
  const nombre = sanitizeStr(req.body.nombre)
  const subdominio = sanitizeStr(req.body.subdominio, 63)?.toLowerCase()
  const nit = sanitizeStr(req.body.nit, 20)
  const plan = sanitizeStr(req.body.plan, 30) || 'emprendedor'
  const estado = sanitizeStr(req.body.estado, 20) || 'prueba'
  const dias_prueba = sanitizeInt(req.body.dias_prueba, 1, 365) || 30
  const max_usuarios = sanitizeInt(req.body.max_usuarios, 1, 200) || MAX_USUARIOS_POR_PLAN[plan] || 3
  const database_url = sanitizeStr(req.body.database_url, 500)
  const contacto_nombre = sanitizeStr(req.body.contacto_nombre)
  const contacto_email = sanitizeStr(req.body.contacto_email, 150)
  const contacto_telefono = sanitizeStr(req.body.contacto_telefono, 30)
  const notas = sanitizeStr(req.body.notas, 1000)
  // Credenciales del primer usuario ERP
  const erp_username = sanitizeStr(req.body.erp_username, 50)
  const erp_password = sanitizeStr(req.body.erp_password, 128)

  // ── Validaciones ─────────────────────────────────────────
  if (!nombre)
    return res.status(400).json({ error: 'El nombre de la empresa es requerido.' })
  if (!subdominio)
    return res.status(400).json({ error: 'El subdominio es requerido.' })
  if (!isValidSubdominio(subdominio))
    return res.status(400).json({ error: 'El subdominio solo puede contener letras minúsculas, números y guiones (sin espacios).' })
  if (!contacto_email || !isValidEmail(contacto_email))
    return res.status(400).json({ error: 'El email de contacto es requerido y debe ser válido.' })
  if (!PLANES_VALIDOS.includes(plan))
    return res.status(400).json({ error: `Plan inválido. Opciones: ${PLANES_VALIDOS.join(', ')}` })
  if (!ESTADOS_VALIDOS.includes(estado))
    return res.status(400).json({ error: `Estado inválido. Opciones: ${ESTADOS_VALIDOS.join(', ')}` })
  if (!erp_username || !erp_password)
    return res.status(400).json({ error: 'El usuario y contraseña ERP son requeridos para provisionar la empresa.' })
  if (erp_password.length < 6)
    return res.status(400).json({ error: 'La contraseña ERP debe tener al menos 6 caracteres.' })

  // ── Verificar subdominio único ───────────────────────────
  try {
    const { rows: existing } = await pool.query(
      'SELECT id FROM empresas WHERE subdominio = $1 AND deleted_at IS NULL',
      [subdominio]
    )
    if (existing.length > 0)
      return res.status(409).json({ error: `El subdominio "${subdominio}" ya está en uso.` })
  } catch (err) {
    console.error('[empresas/create] check subdominio:', err.message)
    return res.status(500).json({ error: 'Error al verificar el subdominio.' })
  }

  // ── Calcular módulos y fecha vencimiento ─────────────────
  const modulos = MODULOS_POR_PLAN[plan] || MODULOS_POR_PLAN.emprendedor
  const fecha_inicio = new Date()
  const fecha_vencimiento = estado === 'prueba'
    ? addDays(fecha_inicio, dias_prueba)
    : req.body.fecha_vencimiento
      ? new Date(req.body.fecha_vencimiento)
      : null

  // ── Garantizar columna erp_username existe ────────────────
  await pool.query(
    `ALTER TABLE empresas ADD COLUMN IF NOT EXISTS erp_username VARCHAR(50)`
  ).catch(err => console.warn('[empresas/create] alter table:', err.message))

  // ── Insertar empresa en BD ───────────────────────────────
  let empresa
  try {
    const { rows } = await pool.query(
      `INSERT INTO empresas
         (nombre, subdominio, nit, plan, estado, fecha_inicio, fecha_vencimiento,
          max_usuarios, database_url, contacto_nombre, contacto_email,
          contacto_telefono, modulos, notas, erp_username)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       RETURNING *`,
      [nombre, subdominio, nit, plan, estado, fecha_inicio, fecha_vencimiento,
        max_usuarios, database_url, contacto_nombre, contacto_email,
        contacto_telefono, JSON.stringify(modulos), notas, erp_username]
    )
    empresa = rows[0]
  } catch (err) {
    console.error('[empresas/create] insert:', err.message)
    return res.status(500).json({ error: 'Error al crear la empresa.' })
  }

  // ── Provisionar Emisor en ERP (no bloquea la respuesta si falla) ──
  const provisionResult = await provisionEmisor({
    empresa_nombre: nombre,
    empresa_nit: nit,
    subdominio,
    username: erp_username,
    password: erp_password,
    plan,
    modulos,
    database_url: database_url || null,
  })

  if (provisionResult.success && provisionResult.emisorId) {
    // Guardar el emisorId de referencia
    await pool.query(
      'UPDATE empresas SET emisor_id = $1 WHERE id = $2',
      [provisionResult.emisorId, empresa.id]
    ).catch(err => console.error('[empresas/create] update emisor_id:', err.message))

    empresa.emisor_id = provisionResult.emisorId
  }

  // ── Enviar email de bienvenida (no bloquea si falla) ──────
  const emailResult = await sendWelcomeEmail(empresa, {
    username: erp_username,
    password: erp_password,
  })

  res.status(201).json({
    success: true,
    data: empresa,
    provisioning: {
      erp: provisionResult.success,
      email: emailResult.sent,
      ...(!provisionResult.success && { erp_error: provisionResult.reason }),
      ...(!emailResult.sent && { email_error: emailResult.reason }),
    },
  })
})

// ══════════════════════════════════════════════════════════
// PATCH /api/empresas/:id — Actualizar empresa
// ══════════════════════════════════════════════════════════
router.patch('/:id', requireAuth, async (req, res) => {
  const id = sanitizeInt(req.params.id, 1, 2147483647)
  if (!id) return res.status(400).json({ error: 'ID de empresa inválido.' })

  try {
    // Obtener empresa actual
    const { rows: current } = await pool.query(
      'SELECT * FROM empresas WHERE id = $1 AND deleted_at IS NULL', [id]
    )
    if (!current[0]) return res.status(404).json({ error: 'Empresa no encontrada.' })
    const empresa = current[0]

    // Extraer sólo los campos enviados
    const nombre = req.body.nombre !== undefined ? sanitizeStr(req.body.nombre) : empresa.nombre
    const nit = req.body.nit !== undefined ? sanitizeStr(req.body.nit, 20) : empresa.nit
    const plan = req.body.plan !== undefined ? sanitizeStr(req.body.plan, 30) : empresa.plan
    const estado = req.body.estado !== undefined ? sanitizeStr(req.body.estado, 20) : empresa.estado
    const max_usuarios = req.body.max_usuarios !== undefined ? sanitizeInt(req.body.max_usuarios, 1, 200) : empresa.max_usuarios
    const database_url = req.body.database_url !== undefined ? sanitizeStr(req.body.database_url, 500) : empresa.database_url
    const contacto_nombre = req.body.contacto_nombre !== undefined ? sanitizeStr(req.body.contacto_nombre) : empresa.contacto_nombre
    const contacto_email = req.body.contacto_email !== undefined ? sanitizeStr(req.body.contacto_email, 150) : empresa.contacto_email
    const contacto_telefono = req.body.contacto_telefono !== undefined ? sanitizeStr(req.body.contacto_telefono, 30) : empresa.contacto_telefono
    const notas = req.body.notas !== undefined ? sanitizeStr(req.body.notas, 1000) : empresa.notas

    let fecha_vencimiento = empresa.fecha_vencimiento
    if (req.body.fecha_vencimiento !== undefined) {
      fecha_vencimiento = req.body.fecha_vencimiento ? new Date(req.body.fecha_vencimiento) : null
    }
    if (req.body.dias_extra !== undefined) {
      const extra = sanitizeInt(req.body.dias_extra, 1, 3650)
      if (extra) {
        const base = fecha_vencimiento && new Date(fecha_vencimiento) > new Date()
          ? new Date(fecha_vencimiento)
          : new Date()
        fecha_vencimiento = addDays(base, extra)
      }
    }

    // Validaciones de campos modificados
    if (plan && !PLANES_VALIDOS.includes(plan))
      return res.status(400).json({ error: `Plan inválido. Opciones: ${PLANES_VALIDOS.join(', ')}` })
    if (estado && !ESTADOS_VALIDOS.includes(estado))
      return res.status(400).json({ error: `Estado inválido. Opciones: ${ESTADOS_VALIDOS.join(', ')}` })
    if (contacto_email && !isValidEmail(contacto_email))
      return res.status(400).json({ error: 'El email de contacto no es válido.' })

    // Si cambió el plan, actualizar módulos automáticamente
    const modulos = (plan !== empresa.plan)
      ? MODULOS_POR_PLAN[plan] || empresa.modulos
      : empresa.modulos

    const { rows: updated } = await pool.query(
      `UPDATE empresas SET
         nombre = $1, nit = $2, plan = $3, estado = $4,
         fecha_vencimiento = $5, max_usuarios = $6, database_url = $7,
         contacto_nombre = $8, contacto_email = $9, contacto_telefono = $10,
         modulos = $11, notas = $12
       WHERE id = $13
       RETURNING *`,
      [nombre, nit, plan, estado, fecha_vencimiento, max_usuarios, database_url,
        contacto_nombre, contacto_email, contacto_telefono,
        JSON.stringify(modulos), notas, id]
    )

    res.json({ success: true, data: updated[0] })
  } catch (err) {
    console.error('[empresas/update]', err.message)
    res.status(500).json({ error: 'Error al actualizar la empresa.' })
  }
})

// ══════════════════════════════════════════════════════════
// DELETE /api/empresas/:id — Soft delete
// ══════════════════════════════════════════════════════════
router.delete('/:id', requireAuth, async (req, res) => {
  const id = sanitizeInt(req.params.id, 1, 2147483647)
  if (!id) return res.status(400).json({ error: 'ID de empresa inválido.' })

  try {
    const { rowCount } = await pool.query(
      'UPDATE empresas SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL', [id]
    )
    if (rowCount === 0)
      return res.status(404).json({ error: 'Empresa no encontrada.' })

    res.json({ success: true, message: 'Empresa eliminada correctamente.' })
  } catch (err) {
    console.error('[empresas/delete]', err.message)
    res.status(500).json({ error: 'Error al eliminar la empresa.' })
  }
})

// ══════════════════════════════════════════════════════════
// POST /api/empresas/check — PÚBLICO — Validar suscripción
// Consumido por el ERP en cada login o request protegido
// ══════════════════════════════════════════════════════════
router.post('/check', async (req, res) => {
  const subdominio = sanitizeStr(req.body.subdominio, 63)?.toLowerCase()

  if (!subdominio)
    return res.status(400).json({ error: 'subdominio es requerido' })

  try {
    const { rows } = await pool.query(
      `SELECT id, nombre, subdominio, plan, estado, fecha_vencimiento,
              max_usuarios, database_url, modulos
       FROM empresas
       WHERE subdominio = $1 AND deleted_at IS NULL`,
      [subdominio]
    )

    const empresa = rows[0]

    // Empresa no encontrada → no autorizado (no revelar si existe o no)
    if (!empresa)
      return res.status(404).json({ valido: false, error: 'Empresa no encontrada' })

    // Estados que bloquean el acceso
    if (empresa.estado === 'suspendida')
      return res.status(402).json({ valido: false, error: 'Cuenta suspendida. Contacta a soporte.' })

    if (empresa.estado === 'cancelada')
      return res.status(402).json({ valido: false, error: 'Cuenta cancelada.' })

    // Verificar si el período de prueba / suscripción venció
    const ahora = new Date()
    const estaVencida = empresa.fecha_vencimiento && new Date(empresa.fecha_vencimiento) <= ahora

    if (estaVencida) {
      // Actualizar estado automáticamente si venció
      await pool.query(
        "UPDATE empresas SET estado = 'suspendida' WHERE id = $1 AND estado NOT IN ('cancelada')",
        [empresa.id]
      ).catch(err => console.error('[empresas/check] auto-suspend:', err.message))

      return res.status(402).json({
        valido: false,
        error: empresa.estado === 'prueba'
          ? 'El período de prueba ha expirado. Activa un plan para continuar.'
          : 'Tu suscripción ha vencido. Renuévala para continuar.',
      })
    }

    // Todo OK
    res.json({
      valido: true,
      empresaId: empresa.id,
      nombre: empresa.nombre,
      plan: empresa.plan,
      estado: empresa.estado,
      fechaVencimiento: empresa.fecha_vencimiento,
      maxUsuarios: empresa.max_usuarios,
      modulos: empresa.modulos,
      databaseUrl: empresa.database_url || null,
    })
  } catch (err) {
    console.error('[empresas/check]', err.message)
    res.status(500).json({ error: 'Error interno del servidor' })
  }
})

module.exports = router
