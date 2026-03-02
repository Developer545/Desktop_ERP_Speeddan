// ══════════════════════════════════════════════════════════
// CONEXIÓN A POSTGRESQL — Compatible con Neon (cloud) y local
// ══════════════════════════════════════════════════════════

require('dotenv').config({ path: require('path').resolve(__dirname, '.env') })
const { Pool } = require('pg')

// ── Construir configuración del Pool ──────────────────────
function buildPoolConfig() {
  // Prioridad: DATABASE_URL (Neon / Vercel / Render)
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      // Neon cierra conexiones idle rápido — mantener pocas
      max: 5,
      idleTimeoutMillis: 30_000,
    }
  }

  // Fallback: variables individuales (desarrollo local)
  return {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '123321',
    database: process.env.DB_NAME || 'speeddansys_licenses',
    port: parseInt(process.env.DB_PORT || '5432'),
  }
}

const pool = new Pool(buildPoolConfig())

pool.on('error', (err) => {
  console.error('[db] Error inesperado en el pool:', err.message)
})

module.exports = pool
