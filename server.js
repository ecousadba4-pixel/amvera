const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { z } = require('zod');
const path = require('path');
const util = require('util');

const app = express();

// Переменные окружения
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_DEVELOPMENT = NODE_ENV === 'development';
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
const AUTH_RATE_LIMIT_WINDOW = Number(process.env.AUTH_RATE_LIMIT_WINDOW) || 15 * 60 * 1000;
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX) || 10;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const IS_DEBUG_LOGGING_ENABLED = LOG_LEVEL === 'debug';
const STATIC_DIR = path.join(__dirname, 'public');

const PASSWORD_HASH_RAW =
  typeof process.env.PASSWORD_HASH === 'string' ? process.env.PASSWORD_HASH.trim() : '';
const PASSWORD_HASH = PASSWORD_HASH_RAW || null;
const BCRYPT_HASH_REGEX = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

if (PASSWORD_HASH && !BCRYPT_HASH_REGEX.test(PASSWORD_HASH)) {
  console.error('❌ PASSWORD_HASH должен быть валидным bcrypt-хешем.');
  process.exit(1);
}

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
app.disable('x-powered-by');

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

const authRateLimiter = rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Слишком много попыток входа, попробуйте позже.'
  }
});

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

const csrfProtection = csrf({
  cookie: {
    key: 'csrf_token',
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production'
  }
});

app.use('/api', csrfProtection);

// Подключение к БД
const PG_POOL_MAX = Number(process.env.PG_POOL_MAX) || 10;
const PG_IDLE_TIMEOUT = Number(process.env.PG_IDLE_TIMEOUT) || 30_000;
const PG_CONNECTION_TIMEOUT = Number(process.env.PG_CONNECTION_TIMEOUT) || 5_000;
const PG_STATEMENT_TIMEOUT = Number(process.env.PG_STATEMENT_TIMEOUT) || 10_000;
const PG_SSL_REJECT_UNAUTHORIZED = String(process.env.PG_SSL_REJECT_UNAUTHORIZED || '').toLowerCase() !== 'false';

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: PG_POOL_MAX,
  idleTimeoutMillis: PG_IDLE_TIMEOUT,
  connectionTimeoutMillis: PG_CONNECTION_TIMEOUT,
  statement_timeout: PG_STATEMENT_TIMEOUT,
  query_timeout: PG_STATEMENT_TIMEOUT,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: PG_SSL_REJECT_UNAUTHORIZED } : false
});

pool.on('error', (error) => {
  console.error('❌ Необработанная ошибка пула БД:', error);
});

const respondWithError = (res, statusCode, message) =>
  res.status(statusCode).json({
    success: false,
    message
  });

const respondWithValidationError = (res, message) => respondWithError(res, 400, message);

const buildPublicErrorMessage = (error, fallbackMessage) =>
  IS_DEVELOPMENT && error instanceof Error ? error.message : fallbackMessage;

const handleUnexpectedError = (res, error, fallbackMessage) => {
  if (IS_DEBUG_LOGGING_ENABLED) {
    console.error(fallbackMessage, error);
  }

  return res.status(500).json({
    success: false,
    message: buildPublicErrorMessage(error, fallbackMessage)
  });
};

class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RequestValidationError';
  }
}

const parseWithSchema = (schema, payload) => {
  const result = schema.safeParse(payload);

  if (!result.success) {
    const firstIssue = result.error.issues[0];
    const message = firstIssue?.message || 'Переданы некорректные данные.';
    throw new RequestValidationError(message);
  }

  return result.data;
};

const toStringSafe = (value) => {
  if (Array.isArray(value)) {
    return toStringSafe(value[0]);
  }

  if (value === undefined || value === null) {
    return '';
  }

  return String(value);
};

const normalizeLoyaltyLevel = (value) =>
  String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');

const LOYALTY_LEVELS = [
  { normalized: '1 сезон', display: '1 СЕЗОН' },
  { normalized: '2 сезона', display: '2 СЕЗОНА' },
  { normalized: '3 сезона', display: '3 СЕЗОНА' },
  { normalized: '4 сезона', display: '4 СЕЗОНА' }
];

const getNextLoyaltyLevel = (currentLevel) => {
  const normalized = normalizeLoyaltyLevel(currentLevel);

  if (!normalized) {
    return LOYALTY_LEVELS[0].display;
  }

  const currentIndex = LOYALTY_LEVELS.findIndex(
    (level) => level.normalized === normalized
  );

  if (currentIndex === -1) {
    return LOYALTY_LEVELS[0].display;
  }

  const nextIndex = Math.min(currentIndex + 1, LOYALTY_LEVELS.length - 1);

  return LOYALTY_LEVELS[nextIndex].display;
};

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

const authSchema = z
  .object({
    password: z
      .string({ required_error: 'Пароль обязателен' })
      .trim()
      .min(1, { message: 'Пароль обязателен' })
      .max(512, { message: 'Пароль слишком длинный' })
  })
  .strict();

const createGuestSchema = z
  .object({
    guest_phone: z.any(),
    last_name: z.any(),
    first_name: z.any(),
    checkin_date: z.any(),
    loyalty_level: z.any().optional(),
    shelter_booking_id: z.any(),
    total_amount: z.any(),
    bonus_spent: z.any().optional()
  })
  .strict()
  .transform((raw, ctx) => {
    let hasError = false;

    const rawPhone = toStringSafe(raw.guest_phone);
    if (!rawPhone) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['guest_phone'],
        message: 'Укажите номер телефона гостя.'
      });
      hasError = true;
    }

    const digits = rawPhone.replace(/\D/g, '');
    if (digits.length < 10) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['guest_phone'],
        message: 'Укажите корректный номер телефона гостя.'
      });
      hasError = true;
    }

    const lastName = toStringSafe(raw.last_name).trim();
    if (!lastName) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['last_name'],
        message: 'Фамилия обязательна.'
      });
      hasError = true;
    } else if (lastName.length > 120) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['last_name'],
        message: 'Фамилия не должна превышать 120 символов.'
      });
      hasError = true;
    }

    const firstName = toStringSafe(raw.first_name).trim();
    if (!firstName) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['first_name'],
        message: 'Имя обязательно.'
      });
      hasError = true;
    } else if (firstName.length > 120) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['first_name'],
        message: 'Имя не должно превышать 120 символов.'
      });
      hasError = true;
    }

    const bookingId = toStringSafe(raw.shelter_booking_id).trim();
    if (!bookingId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['shelter_booking_id'],
        message: 'Укажите номер бронирования Shelter.'
      });
      hasError = true;
    } else if (bookingId.length > 80) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['shelter_booking_id'],
        message: 'Номер бронирования слишком длинный.'
      });
      hasError = true;
    }

    const loyaltyLevelRaw = toStringSafe(raw.loyalty_level).trim();
    if (loyaltyLevelRaw && loyaltyLevelRaw.length > 120) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['loyalty_level'],
        message: 'Уровень лояльности не должен превышать 120 символов.'
      });
      hasError = true;
    }

    const normalizedDate = normalizeCheckinDate(raw.checkin_date);
    if (!normalizedDate) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['checkin_date'],
        message: 'Некорректный формат даты заезда.'
      });
      hasError = true;
    } else if (Number.isNaN(Date.parse(normalizedDate))) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['checkin_date'],
        message: 'Дата заезда не распознана.'
      });
      hasError = true;
    }

    const totalAmountRaw = toStringSafe(raw.total_amount);
    const amount = Number.parseFloat(totalAmountRaw);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['total_amount'],
        message: 'Сумма при выезде должна быть положительным числом не более 1 000 000.'
      });
      hasError = true;
    }

    let bonusValue = 0;
    const bonusRaw = toStringSafe(raw.bonus_spent).trim();
    if (bonusRaw) {
      const parsedBonus = Number.parseInt(bonusRaw, 10);
      if (!Number.isFinite(parsedBonus) || parsedBonus < 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['bonus_spent'],
          message: 'Списанные баллы должны быть неотрицательным числом.'
        });
        hasError = true;
      } else if (parsedBonus > 1_000_000) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['bonus_spent'],
          message: 'Списанные баллы не могут превышать 1 000 000.'
        });
        hasError = true;
      } else {
        bonusValue = parsedBonus;
      }
    }

    if (hasError) {
      return z.NEVER;
    }

    return {
      phone: digits.slice(-10),
      lastName,
      firstName,
      bookingId,
      loyaltyLevel: loyaltyLevelRaw || null,
      checkinDate: normalizedDate,
      totalAmount: amount,
      bonusSpent: bonusValue
    };
  });

const bonusSearchSchema = z
  .object({
    phone: z.any()
  })
  .strict()
  .transform((raw, ctx) => {
    let hasError = false;

    const rawPhone = toStringSafe(raw.phone);
    if (!rawPhone) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['phone'],
        message: 'Не указан номер телефона для поиска.'
      });
      hasError = true;
    }

    const digits = rawPhone.replace(/\D/g, '');
    if (digits.length < 10) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['phone'],
        message: 'Неверный формат номера телефона.'
      });
      hasError = true;
    }

    if (hasError) {
      return z.NEVER;
    }

    return {
      phone: digits.slice(-10)
    };
  });

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

app.get('/api/csrf-token', (req, res) => {
  res.json({
    success: true,
    csrfToken: req.csrfToken()
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
app.post('/api/auth', authRateLimiter, async (req, res) => {
  try {
    if (AUTH_DISABLED) {
      return res.status(200).json({
        success: true,
        message: 'Авторизация отключена администратором'
      });
    }

    const rawPassword =
      typeof req.body?.password === 'string' ? req.body.password : undefined;
    const { password } = parseWithSchema(authSchema, req.body);

    if (!PASSWORD_HASH) {
      console.error('❌ Не задан PASSWORD_HASH для проверки пароля');
      return res.status(500).json({
        success: false,
        message: 'Ошибка конфигурации сервера'
      });
    }

    const candidatePasswords = Array.from(
      new Set(
        [rawPassword, password]
          .map((value) => (typeof value === 'string' ? value : ''))
          .filter((value) => value.length > 0)
      )
    );

    let passwordMatches = false;

    for (const candidate of candidatePasswords) {
      if (await bcrypt.compare(candidate, PASSWORD_HASH)) {
        passwordMatches = true;
        break;
      }
    }

    if (passwordMatches) {
      return res.status(200).json({
        success: true,
        message: 'Доступ разрешён'
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Неверный пароль'
    });
  } catch (error) {
    if (error instanceof RequestValidationError) {
      return respondWithValidationError(res, error.message);
    }

    return handleUnexpectedError(res, error, 'Ошибка при проверке пароля');
  }
});

// Добавление гостя
app.post('/api/guests', async (req, res) => {
  try {
    const guestData = parseWithSchema(createGuestSchema, req.body);

    const query = `
      INSERT INTO guests
      (guest_phone, last_name, first_name, checkin_date, loyalty_level,
       shelter_booking_id, total_amount, bonus_spent)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      guestData.phone,
      guestData.lastName,
      guestData.firstName,
      guestData.checkinDate,
      guestData.loyaltyLevel,
      guestData.bookingId,
      guestData.totalAmount,
      guestData.bonusSpent
    ];

    const result = await pool.query(query, values);

    res.json({
      success: true,
      message: '✅ Данные гостя успешно добавлены!',
      data: result.rows[0]
    });
  } catch (error) {
    if (error instanceof RequestValidationError) {
      return respondWithValidationError(res, error.message);
    }

    return handleUnexpectedError(res, error, '❌ Ошибка при добавлении гостя');
  }
});

// Поиск бонусов по телефону
app.get('/api/bonuses/search', async (req, res) => {
  try {
    const { phone } = parseWithSchema(bonusSearchSchema, req.query);

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
      [phone]
    );

    const guestRecord = result.rows.length ? result.rows[0] : null;

    const responseData = guestRecord
      ? {
          ...guestRecord,
          loyalty_level: getNextLoyaltyLevel(guestRecord.loyalty_level)
        }
      : null;

    res.json({
      success: true,
      data: responseData
    });
  } catch (error) {
    if (error instanceof RequestValidationError) {
      return respondWithValidationError(res, error.message);
    }

    return handleUnexpectedError(res, error, 'Ошибка при поиске гостя');
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
    return handleUnexpectedError(res, error, 'Ошибка при получении списка гостей');
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
    return handleUnexpectedError(res, error, 'Ошибка при получении данных бонусов');
  }
});

// 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: '🚫 Маршрут не найден'
  });
});

// Обработчик ошибок CSRF
app.use((error, req, res, next) => {
  if (error && error.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: 'Недействительный CSRF токен'
    });
  }

  return next(error);
});

// Обработчик ошибок
app.use((error, req, res, next) => {
  if (IS_DEBUG_LOGGING_ENABLED) console.error('Необработанная ошибка:', error);
  res.status(500).json({
    success: false,
    message: buildPublicErrorMessage(error, 'Внутренняя ошибка сервера')
  });
});

// Запуск
const server = app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на Amvera, порт ${PORT}`);
  console.log(`📍 Health check: /health`);
  console.log(`📍 Allowed origins: ${UNIQUE_ALLOWED_ORIGINS.join(', ')}`);
});

const closeServer = util.promisify(server.close.bind(server));

const setupGracefulShutdown = () => {
  let isShuttingDown = false;

  const shutdown = async (signal, error) => {
    if (isShuttingDown) {
      return;
    }

    isShuttingDown = true;

    if (error) {
      console.error(`Получена ошибка ${signal}, завершаем работу:`, error);
    } else {
      console.log(`Получен сигнал ${signal}, начинаем корректное завершение.`);
    }

    try {
      await closeServer();
      console.log('HTTP-сервер остановлен.');
    } catch (closeError) {
      console.error('Ошибка при остановке HTTP-сервера:', closeError);
    }

    try {
      await pool.end();
      console.log('Пул подключений к БД закрыт.');
    } catch (poolError) {
      console.error('Ошибка при закрытии пула БД:', poolError);
    } finally {
      process.exit(error ? 1 : 0);
    }
  };

  ['SIGINT', 'SIGTERM'].forEach((signal) => {
    process.on(signal, () => shutdown(signal));
  });

  process.on('unhandledRejection', (reason) => {
    const rejectionError = reason instanceof Error ? reason : new Error(String(reason));
    shutdown('unhandledRejection', rejectionError);
  });

  process.on('uncaughtException', (uncaughtError) => {
    shutdown('uncaughtException', uncaughtError);
  });
};

setupGracefulShutdown();
