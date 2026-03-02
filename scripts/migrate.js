#!/usr/bin/env node
// ══════════════════════════════════════════════════════════
// MIGRACIÓN — Crear tablas y seed del admin
// Uso: node scripts/migrate.js
// Requiere DATABASE_URL o variables DB_* en .env
// ══════════════════════════════════════════════════════════

require('dotenv').config({ path: require('path').resolve(__dirname, '..', '.env') })
const { Pool } = require('pg')
const bcrypt = require('bcryptjs')

// ── Conexión ──────────────────────────────────────────────
function buildPoolConfig() {
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    }
  }
  return {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '123321',
    database: process.env.DB_NAME || 'speeddansys_licenses',
    port: parseInt(process.env.DB_PORT || '5432'),
  }
}

async function migrate() {
  const pool = new Pool(buildPoolConfig())

  try {
    console.log('🔄 Conectando a la base de datos...')

    // ── Tabla de licencias ────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id              SERIAL PRIMARY KEY,
        license_key     TEXT UNIQUE NOT NULL,
        duration_days   INTEGER NOT NULL,
        client_name     TEXT,
        client_email    TEXT,
        client_phone    TEXT,
        hardware_id     TEXT,
        is_active       BOOLEAN DEFAULT false,
        expiration_date TIMESTAMP,
        initial_username TEXT,
        initial_password TEXT,
        deleted_at      TIMESTAMP DEFAULT NULL,
        created_at      TIMESTAMP DEFAULT NOW()
      )
    `)
    console.log('✅ Tabla "licenses" lista')

    // ── Migraciones incrementales (columnas que podrían faltar) ──
    const alterColumns = [
      'ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_email TEXT',
      'ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_phone TEXT',
      'ALTER TABLE licenses ADD COLUMN IF NOT EXISTS initial_username TEXT',
      'ALTER TABLE licenses ADD COLUMN IF NOT EXISTS initial_password TEXT',
      'ALTER TABLE licenses ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP DEFAULT NULL',
    ]
    for (const sql of alterColumns) {
      await pool.query(sql)
    }

    // ── Tabla de administradores ──────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id            SERIAL PRIMARY KEY,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
      )
    `)
    console.log('✅ Tabla "admin_users" lista')

    // ── Seed: admin por defecto ───────────────────────────
    const { rows } = await pool.query(
      'SELECT id FROM admin_users WHERE username = $1',
      ['admin']
    )
    if (rows.length === 0) {
      const hash = await bcrypt.hash('admin123', 10)
      await pool.query(
        'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
        ['admin', hash]
      )
      console.log('✅ Admin por defecto creado (admin / admin123)')
    } else {
      console.log('ℹ️  Admin ya existe, no se creó duplicado')
    }

    console.log('\n🎉 Migración completada exitosamente.')
  } catch (err) {
    console.error('❌ Error en la migración:', err.message)
    process.exit(1)
  } finally {
    await pool.end()
  }
}

migrate()
