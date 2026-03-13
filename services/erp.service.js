// ══════════════════════════════════════════════════════════
// SERVICE — Comunicación con el API del ERP (Online_ERP)
// ══════════════════════════════════════════════════════════

const ERP_API_URL = process.env.ERP_API_URL
const INTERNAL_KEY = process.env.INTERNAL_API_KEY

/**
 * Llama al endpoint interno del ERP para crear Emisor + primer usuario admin.
 * Si ERP_API_URL o INTERNAL_API_KEY no están configurados, retorna success:false
 * sin lanzar error (el panel sigue funcionando en modo degradado).
 *
 * @param {Object} data
 * @param {string} data.empresa_nombre
 * @param {string} data.empresa_nit
 * @param {string} data.subdominio
 * @param {string} data.username      - Usuario admin inicial del ERP
 * @param {string} data.password      - Contraseña admin inicial del ERP
 * @param {string} data.plan
 * @param {Object} data.modulos
 * @param {string|null} data.database_url  - null = shared DB
 *
 * @returns {Promise<{ success: boolean, emisorId?: number, reason?: string }>}
 */
async function provisionEmisor(data) {
  if (!ERP_API_URL) {
    console.warn('[erp] ERP_API_URL no configurado — provisioning omitido')
    return { success: false, reason: 'ERP_API_URL no configurado' }
  }
  if (!INTERNAL_KEY) {
    console.warn('[erp] INTERNAL_API_KEY no configurado — provisioning omitido')
    return { success: false, reason: 'INTERNAL_API_KEY no configurado' }
  }

  try {
    const response = await fetch(`${ERP_API_URL}/api/seguridad/provision-internal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': INTERNAL_KEY,
      },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(15_000), // 15s timeout
    })

    const result = await response.json()

    if (!response.ok) {
      console.error('[erp] provision-internal respondió con error:', result)
      return { success: false, reason: result.error || `HTTP ${response.status}` }
    }

    console.log(`[erp] Emisor provisionado: id=${result.emisorId}`)
    return { success: true, emisorId: result.emisorId }
  } catch (err) {
    console.error('[erp] Error de conexión al provisionar:', err.message)
    return { success: false, reason: err.message }
  }
}

/**
 * Llama al endpoint interno del ERP para eliminar por completo Emisor + usuarios
 * asociados a ese subdominio.
 *
 * @param {string} subdominio
 * @returns {Promise<{ success: boolean, reason?: string }>}
 */
async function deleteEmisor(subdominio) {
  if (!ERP_API_URL || !INTERNAL_KEY || !subdominio) {
    return { success: false, reason: 'Configuración o subdominio faltante' }
  }

  try {
    const response = await fetch(`${ERP_API_URL}/api/seguridad/provision-internal/${subdominio}`, {
      method: 'DELETE',
      headers: {
        'X-Internal-Key': INTERNAL_KEY,
      },
      signal: AbortSignal.timeout(10_000),
    })

    const result = await response.json()

    if (!response.ok) {
      console.error('[erp] Error al eliminar emisor en ERP:', result)
      return { success: false, reason: result.error || `HTTP ${response.status}` }
    }

    console.log(`[erp] Emisor ${subdominio} depurado correctamente del ERP`)
    return { success: true }
  } catch (err) {
    console.error('[erp] Error de conexión al eliminar emisor:', err.message)
    return { success: false, reason: err.message }
  }
}

module.exports = { provisionEmisor, deleteEmisor }
