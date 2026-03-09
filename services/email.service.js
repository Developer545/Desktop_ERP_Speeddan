// ══════════════════════════════════════════════════════════
// SERVICE — Email con nodemailer
// ══════════════════════════════════════════════════════════

const nodemailer = require('nodemailer')

/** Crea el transporter de nodemailer. Devuelve null si SMTP no está configurado. */
function createTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER) return null

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_PORT === '465',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  })
}

/**
 * Envía el email de bienvenida a una empresa recién creada.
 * @param {Object} empresa   - Registro de la empresa (nombre, subdominio, plan, contacto_email)
 * @param {Object} creds     - { username, password } del primer usuario ERP
 * @returns {Promise<{ sent: boolean, reason?: string }>}
 */
async function sendWelcomeEmail(empresa, creds) {
  const transporter = createTransporter()

  if (!transporter) {
    console.log('[email] SMTP no configurado — email de bienvenida omitido')
    return { sent: false, reason: 'SMTP no configurado' }
  }

  const appUrl = process.env.ERP_APP_URL || 'https://app.speeddansys.com'
  const loginUrl = empresa.subdominio
    ? `${appUrl}/${empresa.subdominio}`
    : appUrl

  const planLabel = {
    emprendedor: 'Emprendedor',
    empresarial: 'Empresarial',
    corporativo_cloud: 'Corporativo Cloud',
    corporativo_local: 'Corporativo Local',
  }[empresa.plan] || empresa.plan

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bienvenido a Speeddansys ERP</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:600px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

    <!-- Header -->
    <div style="background:#111111;padding:36px 40px;text-align:center;">
      <h1 style="color:#f47920;font-size:2rem;margin:0;letter-spacing:-0.5px;">Speeddansys</h1>
      <p style="color:#888;margin:6px 0 0;font-size:0.9rem;">Sistema ERP · El Salvador</p>
    </div>

    <!-- Body -->
    <div style="padding:40px;">
      <h2 style="color:#111;font-size:1.4rem;margin:0 0 8px;">¡Bienvenido, ${empresa.nombre}!</h2>
      <p style="color:#555;line-height:1.7;margin:0 0 24px;">
        Tu cuenta en Speeddansys ERP ha sido creada con el plan
        <strong style="color:#f47920;">${planLabel}</strong>.
        A continuación tus credenciales de acceso:
      </p>

      <!-- Credentials box -->
      <div style="background:#fafafa;border:1.5px solid #e8e8e8;border-radius:10px;padding:24px;margin-bottom:28px;">
        <table style="width:100%;border-collapse:collapse;">
          <tr>
            <td style="padding:6px 0;color:#888;font-size:0.85rem;width:130px;">URL de acceso</td>
            <td style="padding:6px 0;">
              <a href="${loginUrl}" style="color:#f47920;font-weight:600;word-break:break-all;">${loginUrl}</a>
            </td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#888;font-size:0.85rem;">Usuario</td>
            <td style="padding:6px 0;font-weight:600;color:#111;">${creds.username}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#888;font-size:0.85rem;">Contraseña</td>
            <td style="padding:6px 0;font-family:monospace;font-size:1rem;color:#111;letter-spacing:1px;">${creds.password}</td>
          </tr>
        </table>
      </div>

      <!-- CTA -->
      <div style="text-align:center;margin-bottom:32px;">
        <a href="${loginUrl}"
           style="display:inline-block;background:#f47920;color:#fff;padding:14px 36px;border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem;">
          Acceder al sistema →
        </a>
      </div>

      <!-- Security note -->
      <div style="background:#fff8f0;border-left:3px solid #f47920;padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:24px;">
        <p style="margin:0;color:#555;font-size:0.85rem;line-height:1.6;">
          🔐 <strong>Recomendación de seguridad:</strong> cambia tu contraseña al ingresar por primera vez desde
          <em>Configuración → Seguridad</em>.
        </p>
      </div>

      <hr style="border:none;border-top:1px solid #eee;margin:0 0 20px;">
      <p style="margin:0;color:#aaa;font-size:0.78rem;text-align:center;">
        Speeddansys ERP · El Salvador ·
        <a href="mailto:soporte@speeddansys.com" style="color:#aaa;">soporte@speeddansys.com</a>
      </p>
    </div>
  </div>
</body>
</html>`

  try {
    await transporter.sendMail({
      from: `"Speeddansys ERP" <${process.env.SMTP_USER}>`,
      to: empresa.contacto_email,
      subject: `¡Bienvenido a Speeddansys ERP! — ${empresa.nombre}`,
      html,
    })
    console.log(`[email] Bienvenida enviada a ${empresa.contacto_email}`)
    return { sent: true }
  } catch (err) {
    console.error('[email] Error al enviar bienvenida:', err.message)
    return { sent: false, reason: err.message }
  }
}

module.exports = { sendWelcomeEmail }
