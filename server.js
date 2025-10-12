const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Whitelist домены (разрешены только ваши фронтенды)
const allowedOrigins = [
  'https://usadba4.ru',
  // 'https://admin.usadba4.ru' // добавить, если нужна админка
];

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by CORS policy'), false);
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Если нужны куки/авторизация
}));
app.use(express.json());

// Подключение к Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Проверка работы сервера
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 Hotel Guests API работает на Amvera!',
    status: 'OK',
    database: 'Neon PostgreSQL',
    provider: 'Amvera'
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
      error: error.message,
      provider: 'Amvera'
    });
  }
});

// Добавление гостя в таблицу guests
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
    console.error('Ошибка при добавлении гостя:', error);
    res.status(500).json({
      success: false,
      message: '❌ Ошибка при добавлении гостя'
    });
  }
});

// Поиск гостя в таблице bonuses_balance для автозаполнения формы
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

    if (result.rows.length > 0) {
      res.json({
        success: true,
        data: result.rows[0]
      });
    } else {
      res.json({
        success: true,
        data: null
      });
    }

  } catch (error) {
    console.error('Ошибка при поиске гостя в bonuses_balance:', error);
    res.status(500).json({
      success: false,
      message: 'Ошибка при поиске гостя'
    });
  }
});

// Получение всех гостей из таблицы guests (для админки)
app.get('/api/guests', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM guests ORDER BY created_at DESC LIMIT 100');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Ошибка при получении гостей:', error);
    res.status(500).json({
      success: false,
      message: 'Ошибка при получении списка гостей'
    });
  }
});

// Получение всех данных из bonuses_balance (для админки)
app.get('/api/bonuses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bonuses_balance ORDER BY last_date_visit DESC LIMIT 100');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Ошибка при получении данных bonuses_balance:', error);
    res.status(500).json({
      success: false,
      message: 'Ошибка при получении данных бонусов'
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

// Обработка ошибок
app.use((error, req, res, next) => {
  console.error('Необработанная ошибка:', error);
  res.status(500).json({
    success: false,
    message: 'Внутренняя ошибка сервера'
    // error: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    // В продакшене не отдаём подробности пользователю!
  });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на Amvera на порту ${PORT}`);
  console.log(`📍 Health check: https://your-app.amvera.io/health`);
  console.log(`📍 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not connected'}`);
});
