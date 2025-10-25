const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const crypto = require('crypto'); // Для SHA-256
const path = require('path');

const app = express();

// Переменные окружения
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const DATABASE_URL = process.env.DATABASE_URL;
const DEFAULT_BACKEND_HOST = 'u4s-loyalty-karinausadba.amvera.io';

const escapeRegex = (value = '') => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const createWildcardRegex = (pattern) =>
  new RegExp(`^${pattern.split('*').map(escapeRegex).join('.*')}$`, 'i');

const normalizeOriginsList = (raw) =>
  raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const DEFAULT_ALLOWED_ORIGINS = [
  'https://usadba4.ru',
  'https://www.usadba4.ru',
  `https://${DEFAULT_BACKEND_HOST}`,
  'http://localhost',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1',
  'http://127.0.0.1:3000'
];

const configuredOrigins = process.env.ALLOWED_ORIGINS
  ? normalizeOriginsList(process.env.ALLOWED_ORIGINS)
  : [];

const UNIQUE_ALLOWED_ORIGINS = Array.from(
  new Set([...DEFAULT_ALLOWED_ORIGINS, ...configuredOrigins])
);

const EXACT_ALLOWED_ORIGINS = new Set(
  UNIQUE_ALLOWED_ORIGINS.filter((origin) => !origin.includes('*'))
);

const WILDCARD_ORIGINS = UNIQUE_ALLOWED_ORIGINS.filter((origin) =>
  origin.includes('*')
).map(createWildcardRegex);

const isOriginAllowed = (origin) => {
  if (!origin) {
    return true;
  }

  if (EXACT_ALLOWED_ORIGINS.has(origin)) {
    return true;
  }

  return WILDCARD_ORIGINS.some((regex) => regex.test(origin));
};
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'default_cookie_secret';
const RATE_LIMIT_WINDOW = Number(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 100;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const AUTH_DISABLED = String(process.env.DISABLE_AUTH || '').toLowerCase() === 'true';
const STATIC_DIR = path.join(__dirname, 'public');

// Trust proxy для Amvera/cloud
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.json({ limit: '1mb' }));

// Статические ассеты для внутреннего фронтенда
app.use('/app', express.static(STATIC_DIR));
app.get('/app', (req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

// Rate limiting
app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX
}));

// CORS
app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by CORS policy'), false);
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Подключение к БД
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: true } : false
});

// Вспомогательная функция SHA-256
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// === ЭНДПОИНТЫ ===

// Health-check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: '✅ OK',
      database: 'Connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: '❌ Error',
      database: 'Disconnected',
      error: NODE_ENV === 'development' ? error.message : 'DB connection error'
    });
  }
});

app.get('/api/config', (req, res) => {
  res.json({
    authDisabled: AUTH_DISABLED
  });
});

// Главная страница
app.get('/', (req, res) => {
  res.json({
    message: '🚀 Hotel Guests API работает!',
    status: 'OK',
    database: 'Neon PostgreSQL',
    build: process.env.BUILD_VERSION || 'dev'
  });
});

// 🔐 Аутентификация (новый эндпоинт)
app.post('/api/auth', (req, res) => {
  if (AUTH_DISABLED) {
    if (LOG_LEVEL !== 'silent') {
      console.warn('⚠️  Password authentication temporarily disabled via DISABLE_AUTH=true');
    }

    return res.status(200).json({
      success: true,
      message: 'Аутентификация временно отключена'
    });
  }

  const { password } = req.body;

  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      message: 'Пароль обязателен'
    });
  }

  const rawPassword = String(password);
  const trimmedPassword = rawPassword.trim();

  if (!trimmedPassword) {
    return res.status(400).json({
      success: false,
      message: 'Пароль обязателен'
    });
  }

  const candidatePasswords = Array.from(
    new Set(
      [rawPassword, trimmedPassword].filter(pw => typeof pw === 'string' && pw.length > 0)
    )
  );
  const candidateHashes = candidatePasswords.map(pw => sha256(pw));

  const normalizeHash = (hashValue) => {
    if (typeof hashValue !== 'string') {
      return undefined;
    }

    let normalized = hashValue.trim().toLowerCase().replace(/\s+/g, '');

    normalized = normalized.replace(/^(sha-?256[:=]?)/, '');
    normalized = normalized.replace(/^0x/, '');

    return normalized;
  };

  const VALID_HASH = normalizeHash(process.env.PASSWORD_HASH);

  if (!VALID_HASH) {
    console.error('❌ Не задан PASSWORD_HASH для проверки пароля');
    return res.status(500).json({
      success: false,
      message: 'Ошибка конфигурации сервера'
    });
  }

  const hashMatches = candidateHashes.some(hash => hash === VALID_HASH);

  if (hashMatches) {
    return res.status(200).json({
      success: true,
      message: 'Доступ разрешён'
    });
  } else {
    return res.status(401).json({
      success: false,
      message: 'Неверный пароль'
    });
  }
});

// Добавление гостя
app.post('/api/guests', async (req, res) => {
  try {
    const {
      guest_phone,
      last_name,
      first_name,
      checkin_date,
      loyalty_level,
      shelter_booking_id,
      total_amount,
      bonus_spent
    } = req.body;

    if (!guest_phone || !last_name || !first_name) {
      return res.status(400).json({
        success: false,
        message: 'Обязательные поля: номер телефона, фамилия и имя'
      });
    }

    let parsedDate = checkin_date;
    if (checkin_date && checkin_date.includes('.')) {
      const parts = checkin_date.split('.');
      if (parts.length === 3) {
        const [day, month, year] = parts;
        parsedDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
      }
    }

    const query = `
      INSERT INTO guests
      (guest_phone, last_name, first_name, checkin_date, loyalty_level,
       shelter_booking_id, total_amount, bonus_spent)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      guest_phone.replace(/\D/g, '').slice(-10),
      last_name,
      first_name,
      parsedDate,
      loyalty_level,
      shelter_booking_id,
      parseFloat(total_amount) || 0,
      parseInt(bonus_spent) || 0
    ];

    const result = await pool.query(query, values);

    res.json({
      success: true,
      message: '✅ Данные гостя успешно добавлены!',
      data: result.rows[0]
    });
  } catch (error) {
    if (LOG_LEVEL === 'debug') console.error('Ошибка при добавлении гостя:', error);
    res.status(500).json({
      success: false,
      message: NODE_ENV === 'development' ? error.message : '❌ Ошибка при добавлении гостя'
    });
  }
});

// Поиск бонусов по телефону
app.get('/api/bonuses/search', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) {
      return res.status(400).json({
        success: false,
        message: 'Не указан номер телефона для поиска'
      });
    }
    const normalizedPhone = phone.replace(/\D/g, '').slice(-10);

    const result = await pool.query(
      `SELECT
        phone as guest_phone,
        last_name,
        first_name,
        loyalty_level,
        bonus_balances as current_balance,
        visits_total as visits_count,
        last_date_visit as last_visit_date
      FROM bonuses_balance
      WHERE phone = $1
      ORDER BY last_date_visit DESC
      LIMIT 1`,
      [normalizedPhone]
    );

    res.json({
      success: true,
      data: result.rows.length ? result.rows[0] : null
    });
  } catch (error) {
    if (LOG_LEVEL === 'debug') console.error('Ошибка при поиске гостя в bonuses_balance:', error);
    res.status(500).json({
      success: false,
      message: NODE_ENV === 'development' ? error.message : 'Ошибка при поиске гостя'
    });
  }
});

// Получение всех гостей (админ)
app.get('/api/guests', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM guests ORDER BY created_at DESC LIMIT 100');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    if (LOG_LEVEL === 'debug') console.error('Ошибка при получении гостей:', error);
    res.status(500).json({
      success: false,
      message: NODE_ENV === 'development' ? error.message : 'Ошибка при получении списка гостей'
    });
  }
});

// Получение всех бонусов (админ)
app.get('/api/bonuses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bonuses_balance ORDER BY last_date_visit DESC LIMIT 100');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    if (LOG_LEVEL === 'debug') console.error('Ошибка при получении данных bonuses_balance:', error);
    res.status(500).json({
      success: false,
      message: NODE_ENV === 'development' ? error.message : 'Ошибка при получении данных бонусов'
    });
  }
});

// 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: '🚫 Маршрут не найден'
  });
});

// Обработчик ошибок
app.use((error, req, res, next) => {
  if (LOG_LEVEL === 'debug') console.error('Необработанная ошибка:', error);
  res.status(500).json({
    success: false,
    message: NODE_ENV === 'development' ? error.message : 'Внутренняя ошибка сервера'
  });
});

// Запуск
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на Amvera, порт ${PORT}`);
  console.log(`📍 Health check: /health`);
  console.log(`📍 Allowed origins: ${UNIQUE_ALLOWED_ORIGINS.join(', ')}`);
});
