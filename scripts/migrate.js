#!/usr/bin/env node
// ══════════════════════════════════════════════════════════
// MIGRACIÓN — Crear/actualizar tablas y seed inicial
// Uso: node scripts/migrate.js
// ══════════════════════════════════════════════════════════

require('dotenv').config({ path: require('path').resolve(__dirname, '..', '.env') })
const { Pool }  = require('pg')
const bcrypt    = require('bcryptjs')

// ── Conexión ───────────────────────────────────────────────
function buildPoolConfig() {
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    }
  }
  return {
    host:     process.env.DB_HOST     || 'localhost',
    user:     process.env.DB_USER     || 'postgres',
    password: process.env.DB_PASSWORD || '123321',
    database: process.env.DB_NAME     || 'speeddansys_licenses',
    port:     parseInt(process.env.DB_PORT || '5432'),
  }
}

async function migrate() {
  const pool = new Pool(buildPoolConfig())

  try {
    console.log('🔄 Conectando a la base de datos...\n')

    // ──────────────────────────────────────────────────────
    // 1. TABLA: licenses (licencias desktop)
    // ──────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id               SERIAL PRIMARY KEY,
        license_key      TEXT UNIQUE NOT NULL,
        duration_days    INTEGER NOT NULL,
        client_name      TEXT,
        client_email     TEXT,
        client_phone     TEXT,
        hardware_id      TEXT,
        is_active        BOOLEAN DEFAULT false,
        expiration_date  TIMESTAMP,
        initial_username TEXT,
        initial_password TEXT,
        deleted_at       TIMESTAMP DEFAULT NULL,
        created_at       TIMESTAMP DEFAULT NOW()
      )
    `)
    console.log('✅  Tabla "licenses" lista')

    // Columnas incrementales de licenses (retrocompatibilidad)
    const licenseAlters = [
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_email    TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_phone    TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS initial_username TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS initial_password TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS deleted_at      TIMESTAMP DEFAULT NULL",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS database_url    TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS empresa_nombre  TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS empresa_nit     TEXT",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan            TEXT DEFAULT 'basico'",
      "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_users       INTEGER DEFAULT 3",
    ]
    for (const sql of licenseAlters) await pool.query(sql)
    console.log('✅  Columnas de "licenses" actualizadas')

    // ──────────────────────────────────────────────────────
    // 2. TABLA: empresas (suscripciones web)
    // ──────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS empresas (
        id                SERIAL PRIMARY KEY,
        nombre            TEXT NOT NULL,
        subdominio        TEXT UNIQUE,
        nit               TEXT,
        plan              TEXT NOT NULL DEFAULT 'emprendedor',
        estado            TEXT NOT NULL DEFAULT 'prueba',
        fecha_inicio      TIMESTAMP DEFAULT NOW(),
        fecha_vencimiento TIMESTAMP,
        max_usuarios      INTEGER DEFAULT 3,
        database_url      TEXT,
        contacto_nombre   TEXT,
        contacto_email    TEXT NOT NULL,
        contacto_telefono TEXT,
        emisor_id         INTEGER,
        modulos           JSONB DEFAULT '{}',
        notas             TEXT,
        deleted_at        TIMESTAMP DEFAULT NULL,
        created_at        TIMESTAMP DEFAULT NOW()
      )
    `)
    console.log('✅  Tabla "empresas" lista')

    // Columnas incrementales de empresas (retrocompatibilidad)
    const empresasAlters = [
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS subdominio        TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nit               TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS max_usuarios      INTEGER DEFAULT 3",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS database_url      TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS contacto_nombre   TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS contacto_telefono TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS emisor_id         INTEGER",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS modulos           JSONB DEFAULT '{}'",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS notas             TEXT",
      "ALTER TABLE empresas ADD COLUMN IF NOT EXISTS deleted_at        TIMESTAMP DEFAULT NULL",
    ]
    for (const sql of empresasAlters) await pool.query(sql)

    // Índice para búsquedas rápidas por subdominio
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_empresas_subdominio
      ON empresas (subdominio)
      WHERE deleted_at IS NULL AND subdominio IS NOT NULL
    `)
    console.log('✅  Columnas e índices de "empresas" actualizados')

    // ──────────────────────────────────────────────────────
    // 3. TABLA: admin_users
    // ──────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id            SERIAL PRIMARY KEY,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
      )
    `)
    console.log('✅  Tabla "admin_users" lista')

    // ──────────────────────────────────────────────────────
    // 4. SEED: admin por defecto
    // ──────────────────────────────────────────────────────
    const { rows } = await pool.query(
      'SELECT id FROM admin_users WHERE username = $1', ['admin']
    )
    if (rows.length === 0) {
      const hash = await bcrypt.hash('admin123', 10)
      await pool.query(
        'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
        ['admin', hash]
      )
      console.log('✅  Admin por defecto creado (admin / admin123)')
    } else {
      console.log('ℹ️   Admin ya existe, no se creó duplicado')
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
