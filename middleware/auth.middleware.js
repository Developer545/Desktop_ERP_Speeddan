// ══════════════════════════════════════════════════════════
// MIDDLEWARE — Autenticación JWT para el panel admin
// ══════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken')

/**
 * Middleware que verifica el JWT del admin.
 * Acepta cookie `admin_token` o header `Authorization: Bearer <token>`
 */
function requireAuth(req, res, next) {
  const token =
    req.cookies?.admin_token ||
    req.headers.authorization?.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'No autorizado. Inicia sesión primero.' })
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado. Vuelve a iniciar sesión.' })
  }
}

module.exports = { requireAuth }
