const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();

// Переменные окружения
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['https://usadba4.ru'];
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'default_cookie_secret';
const RATE_LIMIT_WINDOW = Number(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 100;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const API_TIMEOUT = Number(process.env.API_TIMEOUT) || 30000;
const PG_SSL = process.env.PG_SSL === 'true';

// Trust proxy для Amvera/cloud (корректная, безопасная конфигурация)
app.set('trust proxy', 1);

// Cookie Parser
app.use(cookieParser(COOKIE_SECRET));

// Rate Limit
app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX
}));

// CORS Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by CORS policy'), false);
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// JSON body parser
app.use(express.json());

// Подключение к Neon PostgreSQL - безопасно!
// Безопасная и строгая версия без шансов для ошибки
const isProduction = NODE_ENV === 'production';
const poolConfig = {
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : false
};
const pool = new Pool(poolConfig);

// Проверка работы сервера
app.get('/', (req, res) => {
  res.json({
    message: '🚀 Hotel Guests API работает на Amvera!',
    status: 'OK',
    database: 'Neon PostgreSQL',
    provider: 'Amvera',
    build: process.env.BUILD_VERSION || 'dev'
  });
});

// Проверка здоровья базы данных
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: '✅ OK',
      database: 'Connected',
      timestamp: new Date().toISOString(),
      provider: 'Amvera'
    });
  } catch (error) {
    res.status(500).json({
      status: '❌ Error',
      database: 'Disconnected',
      error: NODE_ENV === 'development' ? error.message : 'DB connection error',
      provider: 'Amvera'
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

    // Валидация обязательных полей
    if (!guest_phone || !last_name || !first_name) {
      return res.status(400).json({
        success: false,
        message: 'Обязательные поля: номер телефона, фамилия и имя'
      });
    }

    // Парсим дату из формата DD.MM.YYYY
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
      message: '✅ Данные гостя успешно добавлены в базу!',
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

// Получение всех гостей (админка)
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

// Получение всех бонусов (админка)
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

// Обработка 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: '🚫 Маршрут не найден'
  });
});

// Глобальная обработка ошибок
app.use((error, req, res, next) => {
  if (LOG_LEVEL === 'debug') console.error('Необработанная ошибка:', error);
  res.status(500).json({
    success: false,
    message: NODE_ENV === 'development' ? error.message : 'Внутренняя ошибка сервера'
  });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на Amvera на порту ${PORT}`);
  console.log(`📍 Health check: /health`);
  console.log(`📍 Database: ${DATABASE_URL ? 'Connected' : 'Not connected'}`);
});




