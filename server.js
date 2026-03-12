// ══════════════════════════════════════════════════════════
// SERVIDOR DE LICENCIAS — Speeddansys ERP
// Express + PostgreSQL (Neon cloud + Vercel serverless)
// ══════════════════════════════════════════════════════════

const path = require('path')
require('dotenv').config({ path: path.resolve(__dirname, '.env') })

const express = require('express')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
const cookieParser = require('cookie-parser')
const pool = require('./db')

// ── Validar variables de entorno críticas ─────────────────
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET no está definido. Configúralo en .env')
  if (!process.env.VERCEL) process.exit(1)
}

// ── CORS ──────────────────────────────────────────────────
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:4000']

// ── App Express ───────────────────────────────────────────
const app = express()

app.set('trust proxy', 1) // Necesario para Vercel y express-rate-limit

app.use(cors({
  origin: true, // Permitir cualquier origen temporalmente para resolver el bloqueo
  credentials: true,
}))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

// ── Rate Limiting global ──────────────────────────────────
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' },
}))

// ── Rutas ─────────────────────────────────────────────────
app.use('/api/auth', require('./routes/auth'))
app.use('/api/licenses', require('./routes/licencias'))
app.use('/api/empresas', require('./routes/empresas'))

// ── Health Check ──────────────────────────────────────────
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ status: 'ok', timestamp: new Date().toISOString() })
  } catch {
    res.status(503).json({ status: 'error', message: 'Base de datos no disponible' })
  }
})

// ── Iniciar servidor (solo en local, no en Vercel) ────────
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 4000
  app.listen(PORT, () => {
    console.log(`🚀 License Server en http://localhost:${PORT}`)
  })
}

// Exportar para Vercel serverless
module.exports = app
