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
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const DATABASE_URL = process.env.DATABASE_URL;
const DEFAULT_BACKEND_HOST = 'u4s-loyalty-karinausadba.amvera.io';
const AUTH_DISABLED = String(process.env.AUTH_DISABLED || '').toLowerCase() === 'true';

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
const STATIC_DIR = path.join(__dirname, 'public');

const normalizeHash = (hashValue) => {
  if (typeof hashValue !== 'string') {
    return undefined;
  }

  let normalized = hashValue.trim().toLowerCase().replace(/\s+/g, '');

  normalized = normalized.replace(/^(sha-?256[:=]?)/, '');
  normalized = normalized.replace(/^0x/, '');

  if (!/^[a-f0-9]{64}$/i.test(normalized)) {
    return undefined;
  }

  return normalized;
};

const PASSWORD_HASH = normalizeHash(process.env.PASSWORD_HASH);

if (!DATABASE_URL) {
  console.error('❌ Переменная окружения DATABASE_URL не задана. Сервер остановлен.');
  process.exit(1);
}

if (!AUTH_DISABLED && !PASSWORD_HASH) {
  console.error(
    '❌ Не задан PASSWORD_HASH и отключение авторизации не разрешено. Установите PASSWORD_HASH или AUTH_DISABLED=true.'
  );
  process.exit(1);
}

// Trust proxy для Amvera/cloud
app.set('trust proxy', 1);

// Middleware
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
);
app.use(cookieParser(COOKIE_SECRET));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// Статические ассеты для внутреннего фронтенда
app.use('/app', express.static(STATIC_DIR));
app.get('/app', (req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

// Rate limiting
const apiRateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Слишком много запросов, попробуйте позже.'
  }
});
app.use(apiRateLimiter);

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
const PG_POOL_MAX = Number(process.env.PG_POOL_MAX) || 10;
const PG_IDLE_TIMEOUT = Number(process.env.PG_IDLE_TIMEOUT) || 30_000;
const PG_CONNECTION_TIMEOUT = Number(process.env.PG_CONNECTION_TIMEOUT) || 5_000;
const PG_SSL_REJECT_UNAUTHORIZED = String(process.env.PG_SSL_REJECT_UNAUTHORIZED || '').toLowerCase() !== 'false';

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: PG_POOL_MAX,
  idleTimeoutMillis: PG_IDLE_TIMEOUT,
  connectionTimeoutMillis: PG_CONNECTION_TIMEOUT,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: PG_SSL_REJECT_UNAUTHORIZED } : false
});

pool.on('error', (error) => {
  console.error('❌ Необработанная ошибка пула БД:', error.message);
});

// Вспомогательная функция SHA-256
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function normalizeCheckinDate(dateValue) {
  if (!dateValue) {
    return null;
  }

  const raw = String(dateValue).trim();

  if (!raw) {
    return null;
  }

  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    return raw;
  }

  if (/^\d{2}\.\d{2}\.\d{4}$/.test(raw)) {
    const [day, month, year] = raw.split('.');
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
  }

  if (/^\d{2}-\d{2}-\d{4}$/.test(raw)) {
    const [day, month, year] = raw.split('-');
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
  }

  if (/^\d{4}\.\d{2}\.\d{2}$/.test(raw)) {
    const [year, month, day] = raw.split('.');
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
  }

  return null;
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
  const { password } = req.body;

  if (AUTH_DISABLED) {
    return res.status(200).json({
      success: true,
      message: 'Авторизация отключена администратором'
    });
  }

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

  if (!PASSWORD_HASH) {
    console.error('❌ Не задан PASSWORD_HASH для проверки пароля');
    return res.status(500).json({
      success: false,
      message: 'Ошибка конфигурации сервера'
    });
  }

  const hashMatches = candidateHashes
    .map((hash) => normalizeHash(hash))
    .some((hash) => hash === PASSWORD_HASH);

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

    if (!guest_phone || !last_name || !first_name || !shelter_booking_id || !total_amount) {
      return res.status(400).json({
        success: false,
        message: 'Заполните обязательные поля: телефон, фамилия, имя, номер бронирования и сумму.'
      });
    }

    const normalizedPhoneDigits = String(guest_phone).replace(/\D/g, '');
    if (normalizedPhoneDigits.length < 10) {
      return res.status(400).json({
        success: false,
        message: 'Укажите корректный номер телефона гостя.'
      });
    }
    const phoneToStore = normalizedPhoneDigits.slice(-10);

    const lastNameSanitized = String(last_name).trim();
    const firstNameSanitized = String(first_name).trim();
    const bookingSanitized = String(shelter_booking_id).trim();
    const loyaltySanitized = String(loyalty_level || '').trim();
    const normalizedDate = normalizeCheckinDate(checkin_date);

    if (!lastNameSanitized || !firstNameSanitized) {
      return res.status(400).json({
        success: false,
        message: 'Фамилия и имя не могут быть пустыми.'
      });
    }

    if (lastNameSanitized.length > 120 || firstNameSanitized.length > 120) {
      return res.status(400).json({
        success: false,
        message: 'Фамилия и имя не должны превышать 120 символов.'
      });
    }

    if (!bookingSanitized) {
      return res.status(400).json({
        success: false,
        message: 'Укажите номер бронирования Shelter.'
      });
    }

    if (bookingSanitized.length > 80) {
      return res.status(400).json({
        success: false,
        message: 'Номер бронирования слишком длинный.'
      });
    }

    if (!normalizedDate) {
      return res.status(400).json({
        success: false,
        message: 'Некорректный формат даты заезда.'
      });
    }

    if (Number.isNaN(Date.parse(normalizedDate))) {
      return res.status(400).json({
        success: false,
        message: 'Дата заезда не распознана.'
      });
    }

    const amount = Number.parseFloat(total_amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) {
      return res.status(400).json({
        success: false,
        message: 'Сумма при выезде должна быть положительным числом не более 1 000 000.'
      });
    }

    const bonusValueRaw = Number.parseInt(bonus_spent, 10);
    const bonusValue = Number.isFinite(bonusValueRaw) && bonusValueRaw > 0 ? bonusValueRaw : 0;
    if (bonusValue > 1_000_000) {
      return res.status(400).json({
        success: false,
        message: 'Списанные баллы не могут превышать 1 000 000.'
      });
    }

    const query = `
      INSERT INTO guests
      (guest_phone, last_name, first_name, checkin_date, loyalty_level,
       shelter_booking_id, total_amount, bonus_spent)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      phoneToStore,
      lastNameSanitized,
      firstNameSanitized,
      normalizedDate,
      loyaltySanitized || null,
      bookingSanitized,
      amount,
      bonusValue
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
    const digits = String(phone).replace(/\D/g, '');
    if (digits.length < 10) {
      return res.status(400).json({
        success: false,
        message: 'Неверный формат номера телефона'
      });
    }

    const normalizedPhone = digits.slice(-10);

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
