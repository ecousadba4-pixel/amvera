const DEFAULT_BACKEND_HOST = 'u4s-loyalty-karinausadba.amvera.io';
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '0.0.0.0', '[::1]', '']);

const normalizeBase = (value) => {
  if (!value || typeof value !== 'string') {
    return '';
  }
  return value.trim().replace(/\/$/, '');
};

const resolveApiBase = () => {
  if (typeof window === 'undefined') {
    return '';
  }

  const globalBase = normalizeBase(
    window.__LOYALTY_API_BASE__ ||
      window.__AMVERA_API_BASE__ ||
      window.__APP_API_BASE__
  );
  if (globalBase) {
    return globalBase;
  }

  const docEl = document.documentElement;
  const attrBase = normalizeBase(
    docEl?.dataset?.apiBase || docEl?.getAttribute('data-api-base')
  );
  if (attrBase) {
    return attrBase;
  }

  const { protocol, hostname } = window.location;

  if (!hostname || protocol === 'file:') {
    return `https://${DEFAULT_BACKEND_HOST}`;
  }

  if (LOCAL_HOSTNAMES.has(hostname) || hostname.endsWith('.local')) {
    return '';
  }

  if (hostname === DEFAULT_BACKEND_HOST) {
    return '';
  }

  return `https://${DEFAULT_BACKEND_HOST}`;
};

const API_BASE = resolveApiBase();
const API = {
  AUTH: `${API_BASE}/api/auth`,
  SEARCH: `${API_BASE}/api/bonuses/search`,
  ADD: `${API_BASE}/api/guests`
};

const D = (id) => document.getElementById(id);
const normalizePhone = (n) => (n || '').replace(/\D/g, '').slice(-10);
const isValidPhone = (n) => /^\+?7?\d{10}$/.test((n || '').replace(/\D/g, ''));

function formatInteger(n) {
  const value = typeof n === 'number' ? n : parseFloat(n || '0');
  return new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 }).format(Number.isFinite(value) ? value : 0);
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  if (/^\d{4}-\d{2}-\d{2}T/.test(dateStr)) {
    const [y, m, d] = dateStr.slice(0, 10).split('-');
    return `${d}-${m}-${y}`;
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    const [y, m, d] = dateStr.split('-');
    return `${d}-${m}-${y}`;
  }
  if (/^\d{2}-\d{2}-\d{4}$/.test(dateStr)) return dateStr;
  if (/^\d{2}\.\d{2}\.\d{4}$/.test(dateStr)) {
    const [d, m, y] = dateStr.split('.');
    return `${d}-${m}-${y}`;
  }
  if (/^\d{4}\.\d{2}\.\d{2}$/.test(dateStr)) {
    const [y, m, d] = dateStr.split('.');
    return `${d}-${m}-${y}`;
  }
  return dateStr;
}

function formatDateForBackend(dateStr) {
  const [d, m, y] = (dateStr || '').split('-');
  if (d && m && y) return `${d}.${m}.${y}`;
  return dateStr;
}

function getDateMinusTwoDaysYMD() {
  const d = new Date();
  d.setDate(d.getDate() - 2);
  return d.toISOString().split('T')[0];
}

function getDateMinusTwoDaysDisplay() {
  const d = new Date();
  d.setDate(d.getDate() - 2);
  return `${String(d.getDate()).padStart(2, '0')}-${String(d.getMonth() + 1).padStart(2, '0')}-${d.getFullYear()}`;
}

function applyPhoneMask(input) {
  if (!input) return;
  let isDeleting = false;

  input.addEventListener('keydown', (event) => {
    isDeleting = event.key === 'Backspace' || event.key === 'Delete';
  });

  input.addEventListener('input', () => {
    const current = input.value;
    if (isDeleting) {
      isDeleting = false;
      return;
    }

    let digits = current.replace(/\D/g, '');
    if (!digits) {
      input.value = '';
      return;
    }

    if (digits.startsWith('8')) {
      digits = `7${digits.slice(1)}`;
    }
    if (!digits.startsWith('7')) {
      digits = `7${digits}`;
    }

    digits = digits.slice(0, 11);
    const rest = digits.slice(1);
    let formatted = '+7';

    if (rest.length) {
      formatted += ` (${rest.slice(0, 3)}`;
      if (rest.length >= 3) {
        formatted += ')';
      }
    }

    if (rest.length > 3) {
      formatted += ` ${rest.slice(3, 6)}`;
    }

    if (rest.length > 6) {
      formatted += `-${rest.slice(6, 8)}`;
    }

    if (rest.length > 8) {
      formatted += `-${rest.slice(8, 10)}`;
    }

    input.value = formatted;
  });

  input.addEventListener('focus', () => {
    if (!input.value || input.value === '+7') {
      input.value = '+7 ';
      const pos = input.value.length;
      input.setSelectionRange(pos, pos);
    }
  });

  input.addEventListener('blur', () => {
    if (input.value === '+7 ' || input.value === '+7') {
      input.value = '';
    }
  });
}

function unlockAndClear() {
  ['last_name', 'first_name'].forEach((id) => {
    const el = D(id);
    if (el) {
      el.removeAttribute('readonly');
      el.classList.remove('readonly-field');
      el.value = '';
    }
  });
}

function initFlexbeApp() {
  const pass = D('pass');
  const enterBtn = D('enterBtn');
  const wrong = D('wrong-pass');
  const passwordBlock = D('password-block');
  const formBlock = D('form-block');
  const phone = D('guest_phone');
  const msg = D('message');
  const submitBtn = D('submitBtn');
  const nextGuestBtn = D('nextGuestBtn');
  const dateField = D('checkin_date');
  const loyaltyField = D('loyalty_level');
  const form = D('checkout-form');
  let phoneMaskApplied = false;

  const hideMessage = () => {
    if (!msg) return;
    msg.textContent = '';
    msg.className = 'message hidden';
  };

  const showMessage = (type, text) => {
    if (!msg) return;
    msg.textContent = text;
    msg.className = `message ${type}`;
  };

  const setLoading = (isLoading) => {
    if (!submitBtn) return;
    submitBtn.disabled = isLoading;
    submitBtn.classList.toggle('is-loading', isLoading);
  };

  const ensurePhoneMask = () => {
    if (phone && !phoneMaskApplied) {
      applyPhoneMask(phone);
      phoneMaskApplied = true;
    }
  };

  const showMainForm = () => {
    passwordBlock?.classList.add('hidden');
    formBlock?.classList.remove('hidden');

    if (phone) {
      ensurePhoneMask();
      phone.value = '';
      phone.focus();
    }

    if (dateField) {
      dateField.value = getDateMinusTwoDaysYMD();
      dateField.dispatchEvent(new Event('input'));
    }
  };

  if (!pass || !enterBtn || !phone || !dateField || !loyaltyField || !msg || !form || !submitBtn) {
    setTimeout(initFlexbeApp, 300);
    return;
  }

  pass.type = 'password';

  async function checkPassword() {
    wrong?.classList.add('hidden');
    const password = pass.value.trim();

    if (!password) {
      wrong?.classList.remove('hidden');
      return;
    }

    try {
      const resp = await fetch(API.AUTH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const result = await resp.json();

      if (resp.ok && result.success) {
        showMainForm();
      } else {
        wrong?.classList.remove('hidden');
      }
    } catch (err) {
      console.error('Auth error:', err);
      wrong?.classList.remove('hidden');
    }
  }

  enterBtn.onclick = checkPassword;
  pass.onkeydown = (event) => {
    if (event.key === 'Enter') checkPassword();
  };

  const debounce = (fn, ms = 600) => {
    let timeoutId;
    return (...args) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      timeoutId = window.setTimeout(() => fn(...args), ms);
    };
  };

  const updateGuestInfo = debounce(async (val) => {
    const searching = D('searching-guest');
    const guestInfo = D('guest-info');
    const newGuest = D('new-guest-info');
    const phoneError = D('phone-error');

    guestInfo?.classList.add('hidden');
    newGuest?.classList.add('hidden');
    phoneError?.classList.add('hidden');

    if (!isValidPhone(val)) return;

    searching?.classList.remove('hidden');
    try {
      const resp = await fetch(`${API.SEARCH}?phone=${normalizePhone(val)}`);
      const data = await resp.json();
      searching?.classList.add('hidden');

      const guest = data?.data;
      if (guest) {
        const balanceEl = D('balance-points');
        const visitsEl = D('visits-count');
        const lastVisitEl = D('last-visit');
        const lastNameEl = D('last_name');
        const firstNameEl = D('first_name');

        if (balanceEl) balanceEl.textContent = formatInteger(guest.current_balance);
        if (visitsEl) visitsEl.textContent = formatInteger(guest.visits_count);
        if (lastVisitEl) lastVisitEl.textContent = guest.last_visit_date ? formatDate(guest.last_visit_date) : '—';

        if (lastNameEl) {
          lastNameEl.value = guest.last_name || '';
          lastNameEl.setAttribute('readonly', 'readonly');
          lastNameEl.classList.add('readonly-field');
        }
        if (firstNameEl) {
          firstNameEl.value = guest.first_name || '';
          firstNameEl.setAttribute('readonly', 'readonly');
          firstNameEl.classList.add('readonly-field');
        }

        loyaltyField.value = guest.loyalty_level || '';
        loyaltyField.setAttribute('readonly', 'readonly');
        loyaltyField.classList.add('readonly-field');

        guestInfo?.classList.remove('hidden');
      } else {
        newGuest?.classList.remove('hidden');
        unlockAndClear();

        loyaltyField.value = '1 СЕЗОН';
        loyaltyField.setAttribute('readonly', 'readonly');
        loyaltyField.classList.add('readonly-field');
      }
    } catch (error) {
      console.error('Search error:', error);
      searching?.classList.add('hidden');
      phoneError?.classList.remove('hidden');
    }
  });

  phone.addEventListener('input', (event) => {
    const val = event.target.value;
    if (val.replace(/\D/g, '').length < 11) {
      unlockAndClear();
    }
    hideMessage();
    updateGuestInfo(val);
  });

  form.addEventListener('input', hideMessage);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    hideMessage();
    const phoneVal = phone.value;
    const lastNameEl = D('last_name');
    const firstNameEl = D('first_name');
    const amountEl = D('total_amount');
    const bookingEl = D('shelter_booking_id');
    const bonusEl = D('bonus_spent');
    const phoneError = D('phone-error');

    const lastNameVal = lastNameEl?.value.trim();
    const firstNameVal = firstNameEl?.value.trim();
    const amountVal = parseFloat(amountEl?.value || '0');
    const bookingVal = bookingEl?.value.trim();

    if (!isValidPhone(phoneVal)) {
      phoneError?.classList.remove('hidden');
      phone.focus();
      return;
    }
    phoneError?.classList.add('hidden');
    if (!lastNameVal || !firstNameVal) {
      showMessage('error', 'Фамилия и имя не могут быть пустыми');
      return;
    }
    if (!bookingVal) {
      showMessage('error', 'Номер бронирования Shelter обязателен');
      return;
    }
    if (!Number.isFinite(amountVal) || amountVal <= 0) {
      showMessage('error', 'Сумма при выезде должна быть больше 0');
      return;
    }

    const dtRaw = dateField.value;
    const [y, m, d] = dtRaw.split('-');
    const displayStr = d && m && y ? `${d}-${m}-${y}` : getDateMinusTwoDaysDisplay();

    const data = {
      guest_phone: normalizePhone(phoneVal),
      last_name: lastNameVal,
      first_name: firstNameVal,
      checkin_date: formatDateForBackend(displayStr),
      loyalty_level: loyaltyField.value,
      shelter_booking_id: bookingVal,
      total_amount: amountVal,
      bonus_spent: parseFloat(bonusEl?.value || '0') || 0
    };

    setLoading(true);
    try {
      const res = await fetch(API.ADD, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      const result = await res.json();
      const type = result.success ? 'success' : 'error';
      showMessage(type, result.message || (result.success ? 'Успешно' : 'Ошибка'));
      if (result.success) {
        nextGuestBtn?.classList.remove('hidden');
      }
    } catch (error) {
      console.error('Submit error:', error);
      showMessage('error', 'Ошибка отправки данных');
    }
    setLoading(false);
  });

  nextGuestBtn.onclick = () => {
    document.querySelectorAll('.form-input, .form-select').forEach((el) => {
      if ('value' in el) {
        el.value = '';
      }
    });
    D('guest-info')?.classList.add('hidden');
    D('new-guest-info')?.classList.add('hidden');
    nextGuestBtn?.classList.add('hidden');
    phone.value = '';
    dateField.value = getDateMinusTwoDaysYMD();
    loyaltyField.value = '1 СЕЗОН';
    loyaltyField.setAttribute('readonly', 'readonly');
    loyaltyField.classList.add('readonly-field');
    unlockAndClear();
    hideMessage();
    phone.focus();
  };
}

(function waitForFlexbe() {
  if (document.getElementById('enterBtn')) {
    initFlexbeApp();
  } else {
    setTimeout(waitForFlexbe, 300);
  }
})();
