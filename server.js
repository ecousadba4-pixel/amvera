const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const crypto = require('crypto'); // Для SHA-256
const path = require('path');
const util = require('util');
const client = require('prom-client'); // Prometheus metrics

const app = express();

// Переменные окружения
const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_DEVELOPMENT = NODE_ENV === 'development';
const DATABASE_URL = process.env.DATABASE_URL;
const DEFAULT_BACKEND_HOST = 'loyalty-api.usadba4.ru';
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
const IS_DEBUG_LOGGING_ENABLED = LOG_LEVEL === 'debug';
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
const PASSWORD_HASH_BUFFER = PASSWORD_HASH ? Buffer.from(PASSWORD_HASH, 'hex') : null;

if (PASSWORD_HASH_BUFFER && PASSWORD_HASH_BUFFER.length !== 32) {
  console.error('❌ PASSWORD_HASH должен быть валидным SHA-256 (64 hex-символа).');
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

// === Prometheus metrics ===
client.collectDefaultMetrics();

// Гистограмма по HTTP-запросам
const httpRequestDuration = new client.Histogram({
  name: 'loyalty_api_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
});

// Middleware для измерения времени ответа
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer();
  res.on('finish', () => {
    const route = (req.route && req.route.path) || req.path || 'unknown';
    end({
      method: req.method,
      route,
      status_code: res.statusCode
    });
  });
  next();
});

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

// Rate limiting: применяем только к /api/*
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
app.use('/api', apiRateLimiter);

// CORS
app.use(
  cors({
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
  })
);

// Подключение к БД
const PG_POOL_MAX = Number(process.env.PG_POOL_MAX) || 10;
const PG_IDLE_TIMEOUT = Number(process.env.PG_IDLE_TIMEOUT) || 30_000;
const PG_CONNECTION_TIMEOUT = Number(process.env.PG_CONNECTION_TIMEOUT) || 5_000;
const PG_STATEMENT_TIMEOUT = Number(process.env.PG_STATEMENT_TIMEOUT) || 10_000;
const PG_SSL_REJECT_UNAUTHORIZED = String(process.env.PG_SSL_REJECT_UNAUTHORIZED || '')
  .toLowerCase() !== 'false';

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

// Вспомогательная функция SHA-256
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

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

const safeTimingCompare = (candidateHash, expectedBuffer) => {
  if (!candidateHash || !expectedBuffer) {
    return false;
  }

  try {
    const candidateBuffer = Buffer.from(candidateHash, 'hex');

    if (candidateBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(candidateBuffer, expectedBuffer);
  } catch (error) {
    if (IS_DEBUG_LOGGING_ENABLED) {
      console.error('Ошибка при сравнении хеша пароля:', error);
    }

    return false;
  }
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

// Эндпоинт метрик для Prometheus
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', client.register.contentType);
    const metrics = await client.register.metrics();
    res.send(metrics);
  } catch (error) {
    console.error('Ошибка при формировании метрик:', error);
    res.status(500).end('Metrics collection error');
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
    return respondWithValidationError(res, 'Пароль обязателен');
  }

  const rawPassword = String(password);
  const trimmedPassword = rawPassword.trim();

  if (!trimmedPassword) {
    return respondWithValidationError(res, 'Пароль обязателен');
  }

  const candidatePasswords = Array.from(
    new Set(
      [rawPassword, trimmedPassword].filter(
        (pw) => typeof pw === 'string' && pw.length > 0
      )
    )
  );
  const candidateHashes = candidatePasswords.map((pw) => sha256(pw));

  if (!PASSWORD_HASH) {
    console.error('❌ Не задан PASSWORD_HASH для проверки пароля');
    return res.status(500).json({
      success: false,
      message: 'Ошибка конфигурации сервера'
    });
  }

  const hashMatches = candidateHashes
    .map((hash) => normalizeHash(hash))
    .some((hash) => safeTimingCompare(hash, PASSWORD_HASH_BUFFER));

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
      return respondWithValidationError(
        res,
        'Заполните обязательные поля: телефон, фамилия, имя, номер бронирования и сумму.'
      );
    }

    const normalizedPhoneDigits = String(guest_phone).replace(/\D/g, '');
    if (normalizedPhoneDigits.length < 10) {
      return respondWithValidationError(
        res,
        'Укажите корректный номер телефона гостя.'
      );
    }
    const phoneToStore = normalizedPhoneDigits.slice(-10);

    const lastNameSanitized = String(last_name).trim();
    const firstNameSanitized = String(first_name).trim();
    const bookingSanitized = String(shelter_booking_id).trim();
    const loyaltySanitized = String(loyalty_level || '').trim();
    const normalizedDate = normalizeCheckinDate(checkin_date);

    if (!lastNameSanitized || !firstNameSanitized) {
      return respondWithValidationError(
        res,
        'Фамилия и имя не могут быть пустыми.'
      );
    }

    if (lastNameSanitized.length > 120 || firstNameSanitized.length > 120) {
      return respondWithValidationError(
        res,
        'Фамилия и имя не должны превышать 120 символов.'
      );
    }

    if (!bookingSanitized) {
      return respondWithValidationError(
        res,
        'Укажите номер бронирования Shelter.'
      );
    }

    if (bookingSanitized.length > 80) {
      return respondWithValidationError(
        res,
        'Номер бронирования слишком длинный.'
      );
    }

    if (!normalizedDate) {
      return respondWithValidationError(res, 'Некорректный формат даты заезда.');
    }

    if (Number.isNaN(Date.parse(normalizedDate))) {
      return respondWithValidationError(res, 'Дата заезда не распознана.');
    }

    const amount = Number.parseFloat(total_amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) {
      return respondWithValidationError(
        res,
        'Сумма при выезде должна быть положительным числом не более 1 000 000.'
      );
    }

    const bonusValueRaw = Number.parseInt(bonus_spent, 10);
    const bonusValue = Number.isFinite(bonusValueRaw) && bonusValueRaw > 0 ? bonusValueRaw : 0;
    if (bonusValue > 1_000_000) {
      return respondWithValidationError(
        res,
        'Списанные баллы не могут превышать 1 000 000.'
      );
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
    return handleUnexpectedError(res, error, '❌ Ошибка при добавлении гостя');
  }
});

// Поиск бонусов по телефону
app.get('/api/bonuses/search', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) {
      return respondWithValidationError(res, 'Не указан номер телефона для поиска');
    }
    const digits = String(phone).replace(/\D/g, '');
    if (digits.length < 10) {
      return respondWithValidationError(res, 'Неверный формат номера телефона');
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
    return handleUnexpectedError(res, error, 'Ошибка при поиске гостя');
  }
});

// Получение всех гостей (админ)
app.get('/api/guests', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM guests ORDER BY created_at DESC LIMIT 100'
    );
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
    const result = await pool.query(
      'SELECT * FROM bonuses_balance ORDER BY last_date_visit DESC LIMIT 100'
    );
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
    const rejectionError =
      reason instanceof Error ? reason : new Error(String(reason));
    shutdown('unhandledRejection', rejectionError);
  });

  process.on('uncaughtException', (uncaughtError) => {
    shutdown('uncaughtException', uncaughtError);
  });
};

setupGracefulShutdown();

