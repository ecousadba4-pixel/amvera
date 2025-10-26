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
  ADD: `${API_BASE}/api/guests`,
  CONFIG: `${API_BASE}/api/config`
};

const configState = {
  loaded: false,
  authDisabled: false
};

const loadServerConfig = async () => {
  if (configState.loaded) {
    return configState;
  }

  try {
    const response = await fetch(API.CONFIG, {
      method: 'GET',
      credentials: 'include',
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`Config request failed with status ${response.status}`);
    }

    const data = await response.json();
    configState.authDisabled = Boolean(data?.authDisabled);
  } catch (error) {
    console.warn('Не удалось получить конфигурацию сервера:', error);
    configState.authDisabled = false;
  } finally {
    configState.loaded = true;
  }

  return configState;
};

const D = (id) => document.getElementById(id);
const PHONE_REQUIRED_DIGITS = 11;
const normalizePhone = (n) => (n || '').replace(/\D/g, '').slice(-10);
const isValidPhone = (n) => /^\+?7?\d{10}$/.test((n || '').replace(/\D/g, ''));
const extractDigits = (value) => (value || '').replace(/\D/g, '');

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

async function initFlexbeApp() {
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
    submitBtn.dataset.loading = isLoading ? 'true' : 'false';
    submitBtn.disabled = isLoading || submitBtn.dataset.phoneLocked === 'true';
    submitBtn.classList.toggle('is-loading', isLoading);
  };

  const ensurePhoneMask = () => {
    if (phone && !phoneMaskApplied) {
      applyPhoneMask(phone);
      phoneMaskApplied = true;
    }
  };

  if (!pass || !enterBtn || !phone || !dateField || !loyaltyField || !msg || !form || !submitBtn) {
    setTimeout(initFlexbeApp, 300);
    return;
  }

  const guestInfo = D('guest-info');
  const newGuest = D('new-guest-info');
  const phoneError = D('phone-error');
  const phoneIncomplete = D('phone-incomplete');
  const searching = D('searching-guest');
  const authBanner = D('auth-disabled-banner');
  const dependentElements = Array.from(form.querySelectorAll('[data-requires-phone]'));

  const defaultWrongText = (wrong?.textContent || 'Неверный пароль!').trim();
  const phoneErrorDefaultText = (phoneError?.textContent || '⚠️ Неверный формат номера').trim();

  const showPasswordError = (text) => {
    if (!wrong) return;
    if (!text) {
      wrong.textContent = defaultWrongText;
      wrong.classList.add('hidden');
      return;
    }
    wrong.textContent = text;
    wrong.classList.remove('hidden');
  };

  const showPhoneError = (text) => {
    if (!phoneError) return;
    if (!text) {
      phoneError.textContent = phoneErrorDefaultText;
      phoneError.classList.add('hidden');
      return;
    }
    phoneError.textContent = text;
    phoneError.classList.remove('hidden');
  };

  const setDependentFieldsEnabled = (enabled) => {
    dependentElements.forEach((el) => {
      if (!enabled) {
        el.dataset.phoneLocked = 'true';
        el.disabled = true;
        return;
      }

      delete el.dataset.phoneLocked;
      if (el === submitBtn) {
        el.disabled = el.dataset.loading === 'true';
      } else {
        el.disabled = false;
      }
    });
  };

  let lastSearchRequestId = 0;

  const showMainForm = () => {
    passwordBlock?.classList.add('hidden');
    formBlock?.classList.remove('hidden');
    showPasswordError();
    nextGuestBtn?.classList.add('hidden');

    if (pass) {
      pass.value = '';
    }

    if (phone) {
      ensurePhoneMask();
      phone.value = '';
      phone.focus();
    }

    if (dateField) {
      dateField.value = getDateMinusTwoDaysYMD();
      dateField.dispatchEvent(new Event('input'));
    }

    unlockAndClear();
    loyaltyField.value = '';
    loyaltyField.removeAttribute('readonly');
    loyaltyField.classList.remove('readonly-field');

    setDependentFieldsEnabled(false);
    phoneIncomplete?.classList.add('hidden');
    guestInfo?.classList.add('hidden');
    newGuest?.classList.add('hidden');
    searching?.classList.add('hidden');
    showPhoneError();
    hideMessage();
  };

  setDependentFieldsEnabled(false);

  pass.type = 'password';

  const applyAuthState = (isDisabled) => {
    if (isDisabled) {
      authBanner?.classList.remove('hidden');
      showMainForm();
    } else {
      authBanner?.classList.add('hidden');
      passwordBlock?.classList.remove('hidden');
      formBlock?.classList.add('hidden');
      showPasswordError();
      pass?.focus();
    }
  };

  const config = await loadServerConfig();
  applyAuthState(config.authDisabled);

  async function checkPassword() {
    if (configState.authDisabled) {
      showMainForm();
      return;
    }

    const password = pass.value.trim();

    if (!password) {
      showPasswordError('Пароль обязателен');
      return;
    }

    try {
      const resp = await fetch(API.AUTH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const result = await resp.json().catch(() => ({}));

      if (resp.ok && result?.success) {
        showMainForm();
      } else {
        const message = result?.message || 'Неверный пароль';
        showPasswordError(message);
      }
    } catch (error) {
      console.error('Auth error:', error);
      showPasswordError('Не удалось проверить пароль. Проверьте соединение.');
    }
  }

  enterBtn.onclick = () => {
    void checkPassword();
  };
  pass.onkeydown = (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void checkPassword();
    }
  };

  const debounce = (fn, ms = 600) => {
    let timeoutId;
    const debounced = (...args) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      timeoutId = window.setTimeout(() => {
        timeoutId = null;
        fn(...args);
      }, ms);
    };
    debounced.cancel = () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
    };
    return debounced;
  };

  const updateGuestInfo = debounce(async (val) => {
    guestInfo?.classList.add('hidden');
    newGuest?.classList.add('hidden');
    showPhoneError();

    if (!isValidPhone(val)) {
      searching?.classList.add('hidden');
      return;
    }

    const requestId = ++lastSearchRequestId;
    searching?.classList.remove('hidden');

    try {
      const resp = await fetch(`${API.SEARCH}?phone=${normalizePhone(val)}`);
      const data = await resp.json().catch(() => ({}));

      if (requestId !== lastSearchRequestId) {
        return;
      }

      searching?.classList.add('hidden');

      if (!resp.ok || data?.success === false) {
        throw new Error(data?.message || 'Ошибка поиска гостя');
      }

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
      if (requestId !== lastSearchRequestId) {
        return;
      }
      console.error('Search error:', error);
      searching?.classList.add('hidden');
      showPhoneError('⚠️ Не удалось получить данные гостя. Попробуйте позже.');
      showMessage('error', 'Не удалось получить данные гостя. Попробуйте позже.');
    }
  });

  phone.addEventListener('input', (event) => {
    const val = event.target.value;
    const digits = extractDigits(val);
    const digitsCount = digits.length;
    const hasAnyDigits = digitsCount > 0;
    const isCompletePhone = isValidPhone(val) && digitsCount === PHONE_REQUIRED_DIGITS;

    hideMessage();
    showPhoneError();

    if (!isCompletePhone) {
      lastSearchRequestId++;
      updateGuestInfo.cancel();
      setDependentFieldsEnabled(false);
      unlockAndClear();
      loyaltyField.value = '';
      loyaltyField.removeAttribute('readonly');
      loyaltyField.classList.remove('readonly-field');
      guestInfo?.classList.add('hidden');
      newGuest?.classList.add('hidden');
      searching?.classList.add('hidden');
      phoneIncomplete?.classList.toggle('hidden', !hasAnyDigits);
      nextGuestBtn?.classList.add('hidden');
      return;
    }

    phoneIncomplete?.classList.add('hidden');
    setDependentFieldsEnabled(true);
    updateGuestInfo(val);
  });

  form.addEventListener('input', hideMessage);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    hideMessage();
    showPhoneError();
    const phoneVal = phone.value;
    const lastNameEl = D('last_name');
    const firstNameEl = D('first_name');
    const amountEl = D('total_amount');
    const bookingEl = D('shelter_booking_id');
    const bonusEl = D('bonus_spent');

    const lastNameVal = lastNameEl?.value.trim();
    const firstNameVal = firstNameEl?.value.trim();
    const amountVal = parseFloat(amountEl?.value || '0');
    const bookingVal = bookingEl?.value.trim();

    if (!isValidPhone(phoneVal)) {
      showPhoneError(phoneErrorDefaultText);
      phone.focus();
      return;
    }
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
      const result = await res.json().catch(() => ({}));

      if (!res.ok || result?.success === false) {
        const errorMessage = result?.message || 'Ошибка отправки данных';
        showMessage('error', errorMessage);
        return;
      }

      showMessage('success', result.message || 'Успешно');
      if (result.success !== false) {
        nextGuestBtn?.classList.remove('hidden');
      }
    } catch (error) {
      console.error('Submit error:', error);
      showMessage('error', 'Не удалось отправить данные. Проверьте соединение.');
    } finally {
      setLoading(false);
    }
  });

  nextGuestBtn.onclick = () => {
    document.querySelectorAll('.form-input, .form-select').forEach((el) => {
      if ('value' in el) {
        el.value = '';
      }
    });
    guestInfo?.classList.add('hidden');
    newGuest?.classList.add('hidden');
    nextGuestBtn?.classList.add('hidden');
    if (phone) {
      phone.value = '';
      ensurePhoneMask();
    }
    if (dateField) {
      dateField.value = getDateMinusTwoDaysYMD();
      dateField.dispatchEvent(new Event('input'));
    }
    loyaltyField.value = '1 СЕЗОН';
    loyaltyField.setAttribute('readonly', 'readonly');
    loyaltyField.classList.add('readonly-field');
    unlockAndClear();
    setDependentFieldsEnabled(false);
    searching?.classList.add('hidden');
    showPhoneError();
    phoneIncomplete?.classList.add('hidden');
    hideMessage();
    phone?.focus();
  };
}


(function waitForFlexbe() {
  if (document.getElementById('enterBtn')) {
    initFlexbeApp();
  } else {
    setTimeout(waitForFlexbe, 300);
  }
})();
