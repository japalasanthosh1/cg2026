import express from 'express';
import { neon } from '@neondatabase/serverless';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import { body, validationResult } from 'express-validator';

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Trust the reverse proxy (Railway/Render) so rate limiters don't block everyone
app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      frameSrc: ["'self'", "https://maps.google.com", "https://www.google.com"],
      connectSrc: ["'self'"]
    }
  }
}));
app.use(cors());

// Enable JSON body parsing for API requests
app.use(express.json());

// Protect against HTTP Parameter Pollution
app.use(hpp());

// Rate Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP, please try again after 15 minutes' }
});

const applyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // Limit each IP to 50 applications per hour
  message: { error: 'Application limit reached. Please try again later.' }
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 admin requests per 15 mins
  message: { error: 'Too many admin attempts. Please try again later.' }
});

app.use(globalLimiter);

// Initialize Neon SQL driver securely
const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;

if (!sql) {
  console.warn("⚠️ WARNING: DATABASE_URL is missing. Database operations will fail.");
}

// Secure API Endpoint for handling form submissions
app.post('/api/apply', applyLimiter, [
  body('id').isString().trim().escape(),
  body('name').isString().notEmpty().trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('phone').isString().trim().escape(),
  body('type').isString().trim().escape(),
  body('org').isString().trim().escape(),
  body('role').isString().trim().escape(),
  body('linkedin').optional({ checkFalsy: true }).isString().trim(),
  body('github').optional({ checkFalsy: true }).isString().trim(),
  body('portfolio').optional({ checkFalsy: true }).isString().trim(),
  body('interests').isArray(),
  body('interests.*').isString().trim().escape(),
  body('status').isString().trim().escape(),
  body('timestamp').isISO8601()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('[API] Validation failed:', errors.array());
    return res.status(400).json({ error: 'Validation Error', messages: errors.array() });
  }

  try {
    const { 
      id, name, email, phone, type, org, role, 
      linkedin, github, portfolio, interests, status, timestamp 
    } = req.body;

    console.log(`[API] Received application from ${name} (${email})`);

    // Check for duplicate email or phone
    const existing = await sql`
      SELECT id FROM applications WHERE email = ${email} OR phone = ${phone} LIMIT 1
    `;

    if (existing.length > 0) {
      console.log(`[API] Rejected duplicate application from ${email}`);
      return res.status(409).json({ error: 'Duplicate', message: 'You have already applied.' });
    }

    // Insert into database safely using parameterized query syntax
    await sql`
      INSERT INTO applications (
        id, name, email, phone, type, org, role, linkedin, github, portfolio, interests, status, timestamp
      ) VALUES (
        ${id}, ${name}, ${email}, ${phone}, ${type}, ${org}, ${role}, 
        ${linkedin}, ${github || ''}, ${portfolio || ''}, ${interests || []}, ${status}, ${timestamp}
      )
    `;

    res.status(200).json({ success: true, message: 'Application submitted successfully.' });
  } catch (error) {
    console.error('[API] Database Insertion Error:', error.message);
    res.status(500).json({ error: 'Database Error' });
  }
});

// --- SECURE ADMIN API ENDPOINTS ---
app.use('/api/admin', adminLimiter);

const requireAdmin = (req, res, next) => {
  const pin = req.headers['authorization'];
  if (pin !== process.env.ADMIN_PIN) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid Admin PIN' });
  }
  next();
};

app.post('/api/admin/auth', (req, res) => {
  const { pin } = req.body;
  if (pin === process.env.ADMIN_PIN) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid PIN' });
  }
});

app.get('/api/admin/applications', requireAdmin, async (req, res) => {
  try {
    const applications = await sql`SELECT * FROM applications ORDER BY timestamp DESC`;
    res.json(applications);
  } catch (error) {
    console.error('[API] Admin Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

app.post('/api/admin/status', requireAdmin, async (req, res) => {
  const { id, status } = req.body;
  try {
    await sql`UPDATE applications SET status = ${status} WHERE id = ${id}`;
    res.json({ success: true });
  } catch (error) {
    console.error('[API] Admin Status Error:', error.message);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

app.post('/api/admin/mock', requireAdmin, async (req, res) => {
  try {
    const ts = new Date().toISOString();
    await sql`
      INSERT INTO applications (id, name, email, phone, type, org, role, linkedin, github, portfolio, interests, status, timestamp) 
      VALUES 
      ('CG-MOCK-01', 'Jane Doe', 'jane@example.com', '1234567890', 'In-Person', 'Example Corp', 'Software Engineer', 'linkedin.com', 'github.com', '', '{"AI","Product"}', 'Pending', ${ts}),
      ('CG-MOCK-02', 'John Smith', 'john@acme.com', '0987654321', 'Virtual', 'Acme Inc', 'Product Manager', '', '', '', '{"Design"}', 'Admitted', ${ts})
    `;
    res.json({ success: true });
  } catch (error) {
    console.error('[API] Admin Mock Error:', error.message);
    res.status(500).json({ error: 'Failed to insert mock data' });
  }
});

app.post('/api/admin/clear', requireAdmin, async (req, res) => {
  try {
    await sql`DELETE FROM applications`;
    res.json({ success: true });
  } catch (error) {
    console.error('[API] Admin Clear Error:', error.message);
    res.status(500).json({ error: 'Failed to clear database' });
  }
});


// Serve the static frontend files (index.html, app.js, styles.css, etc.)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
  console.log(`📡 Securely connected to Neon Database.`);
});
