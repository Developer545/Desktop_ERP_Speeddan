// ══════════════════════════════════════════════════════════
// UTILS — Validadores y sanitizadores compartidos
// ══════════════════════════════════════════════════════════

/**
 * Sanitiza un string: trim, limita longitud, devuelve null si vacío
 * @param {*} val
 * @param {number} maxLen
 * @returns {string|null}
 */
function sanitizeStr(val, maxLen = 255) {
  if (typeof val !== 'string') return null
  return val.trim().slice(0, maxLen) || null
}

/**
 * Sanitiza un entero dentro de un rango
 * @param {*} val
 * @param {number} min
 * @param {number} max
 * @returns {number|null}
 */
function sanitizeInt(val, min = 1, max = 36500) {
  const n = parseInt(val)
  if (isNaN(n) || n < min || n > max) return null
  return n
}

/**
 * Valida formato de email básico
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

/**
 * Valida que un subdominio solo contenga letras, números y guiones
 * y no empiece/termine con guión
 * @param {string} sub
 * @returns {boolean}
 */
function isValidSubdominio(sub) {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(sub)
}

/**
 * Suma días a una fecha
 * @param {Date} date
 * @param {number} days
 * @returns {Date}
 */
function addDays(date, days) {
  const result = new Date(date)
  result.setDate(result.getDate() + days)
  return result
}

/**
 * Comprueba si dateA > dateB
 */
function isAfter(dateA, dateB) {
  return new Date(dateA) > new Date(dateB)
}

module.exports = { sanitizeStr, sanitizeInt, isValidEmail, isValidSubdominio, addDays, isAfter }
