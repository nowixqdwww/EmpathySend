let ws
let currentUser = null
let currentChat = null
let videoMaxDuration = 60  // секунд
let reconnectAttempts = 0
const maxReconnectAttempts = 10
let currentUserProfile = null
let typingTimeout = null
let reconnectTimeout = null
let pingInterval = null
let isConnected = false
let selectedMessageId = null
let selectedMessageElement = null
let selectedChatPhone = null
let selectedChatElement = null

// Для долгого нажатия
let longPressTimer = null
let longPressTarget = null

// Для поиска
let searchTimeout = null

// Для редактора аватара
let cropper = null
let currentAvatarFile = null

// Для стикеров
let userStickers = []
let popularStickers = [
    '/static/stickers/popular/1.svg',
    '/static/stickers/popular/2.svg',
    '/static/stickers/popular/3.svg',
    '/static/stickers/popular/4.svg',
    '/static/stickers/popular/5.svg'
]

// Глобальный объект для хранения онлайн статусов
window.clients = {}

// last_seen и переменные пересылки
const lastSeenMap = {}
let selectedMessageText = null
let selectedMessageSender = null

// Хранилище чатов и непрочитанных сообщений
let chatsCache = {}
let unreadCounts = {}

// ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============

// ── Last seen ──────────────────────────────────────────────
function pluralize(n, one, few, many) {
    const m10 = n % 10, m100 = n % 100
    if (m10 === 1 && m100 !== 11) return one
    if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few
    return many
}
function formatLastSeen(iso) {
    if (!iso) return 'был(а) давно'
    // Добавляем Z если нет timezone-суффикса (PostgreSQL возвращает без Z)
    const isoFixed = /[Z+]/.test(iso) ? iso : iso + 'Z'
    const diff = Math.floor((Date.now() - new Date(isoFixed)) / 1000)
    const min  = Math.floor(diff / 60)
    const hour = Math.floor(min  / 60)
    const day  = Math.floor(hour / 24)
    const d    = new Date(isoFixed)
    const t    = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    if (diff < 60)  return 'был(а) только что'
    if (min  < 60)  return `был(а) ${min} ${pluralize(min, 'минуту', 'минуты', 'минут')} назад`
    if (hour < 24)  return `был(а) сегодня в ${t}`
    if (day  === 1) return `был(а) вчера в ${t}`
    if (day  < 7)   return `был(а) ${day} ${pluralize(day, 'день', 'дня', 'дней')} назад`
    return `был(а) ${d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' })}`
}
function updateChatStatusText(phone, isOnline) {
    const el = document.getElementById('chatUserStatus')
    if (!el) return
    if (isOnline) {
        el.textContent = 'онлайн'
        el.className = 'chat-user-status'
    } else {
        el.textContent = lastSeenMap[phone] ? formatLastSeen(lastSeenMap[phone]) : 'оффлайн'
        el.className = 'chat-user-status offline'
    }
}

// ── Emoji utils ────────────────────────────────────────────
function splitEmoji(str) {
    if (typeof Intl !== 'undefined' && Intl.Segmenter) {
        return [...new Intl.Segmenter().segment(str)].map(s => s.segment)
    }
    return [...str]
}
const EMOJI_CATEGORIES = [
    { id:'smileys',    icon:'😀', label:'Смайлы',
      emojis: splitEmoji('😀😃😄😁😆😅🤣😂🙂🙃😉😊😇🥰😍🤩😘😗😚😙🥲😋😛😜🤪😝🤑🤗🤭🤫🤔🤐🤨😐😑😶😏😒🙄😬🤥😌😔😪🤤😴😷🤒🤕🤢🤮🤧🥵🥶🥴😵🤯🤠🥳🥸😎🤓🧐😕😟🙁☹️😮😯😲😳🥺😦😧😨😰😥😢😭😱😖😣😞😓😩😫🥱😤😡😠🤬😈👿💀☠️💩🤡👹👺👻👽👾🤖') },
    { id:'gestures',   icon:'👋', label:'Жесты',
      emojis: splitEmoji('👋🤚🖐✋🖖👌🤌🤏✌️🤞🤟🤘🤙👈👉👆🖕👇☝️👍👎✊👊🤛🤜👏🙌🫶👐🤲🤝🙏✍️💅🤳💪🦾🦿🦵🦶👂🦻👃🧠👀👁👅👄💋') },
    { id:'people',     icon:'👤', label:'Люди',
      emojis: splitEmoji('👶🧒👦👧🧑👱👨🧔👩🧓👴👵🙍🙎🙅🙆💁🙋🧏🙇🤦🤷👮🕵️💂🥷👷🤴👸👲🧕🤵👰🤰🤱👼🎅🤶🦸🦹🧙🧚🧛🧜🧝🧞🧟🧌💆💇🚶🧍🧎🏃💃🕺👯🧖🧗🧘🛀🛌👫👬👭💏💑👪') },
    { id:'nature',     icon:'🌿', label:'Природа',
      emojis: splitEmoji('🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🙈🙉🙊🐔🐧🐦🐤🦆🦅🦉🦇🐺🐗🐴🦄🐝🐛🦋🐌🐞🐜🦟🦗🕷🦂🐢🐍🦎🐙🦑🦐🦀🐡🐠🐟🐬🐳🦈🐊🐅🐆🦓🦍🐘🦛🦏🐪🦒🦘🦬🌸🌺🌻🌹🌷🌼🌱🌿☘️🍀🍃🍂🍁🍄🌾💐🌵🌴🌳🌲🌙⭐🌟💫✨☀️⛅🌧️🌨️❄️🌊🌈') },
    { id:'food',       icon:'🍕', label:'Еда',
      emojis: splitEmoji('🍏🍎🍐🍊🍋🍌🍉🍇🍓🫐🍒🍑🥭🍍🥥🥝🍅🍆🥑🥦🥬🥒🌶️🧄🧅🥔🍠🥜🍞🥐🥖🧀🥚🍳🧈🥞🧇🥓🥩🍗🍖🌭🍔🍟🍕🌮🌯🍜🍝🍛🍲🍣🍱🥟🍤🍙🍚🍘🍥🥮🧁🍰🎂🍮🍭🍬🍫🍿🍩🍪☕🍵🍺🍻🥂🍷🥃🍸🍹🧃🥤🧋🍾') },
    { id:'activities', icon:'⚽', label:'Активности',
      emojis: splitEmoji('⚽🏀🏈⚾🥎🎾🏐🏉🥏🎱🏓🏸🏒⛳🎣🤿🎽🎿🛷🎯🎲🎮🕹️🎰🧩♟️🎭🎨🎪🎢🎡🎠🚀🎆🎇🧨🎉🎊🎈🎁🎀🏆🥇🥈🥉🎤🎧🎼🎵🎶🥁🎷🎺🎸🎻') },
    { id:'symbols',    icon:'❤️', label:'Символы',
      emojis: splitEmoji('❤️🧡💛💚💙💜🖤🤍🤎💔💕💞💓💗💖💘💝💟☮️✝️☪️🕉️☯️🛐💯🔥⭐✨💫⚡🌈💎👑🎯🔑🔒🔓💡🔍🔎📌📍🌍🌎🌏🚩🎌🏁❌✅⚠️🚫🔞🔄🔃🔝🔛🔜🔚🔙') }
]
const EMOJI_NAMES = {
    '😀':'радость','😂':'смех','😭':'плачет','😍':'влюблён','😎':'круто','😊':'улыбка',
    '😢':'грустно','😡':'злость','🥰':'любовь','🤔':'думает','👍':'лайк','👎':'дизлайк',
    '❤️':'сердце','🔥':'огонь','💯':'сто','🎉':'праздник','🙏':'спасибо','💪':'сила',
    '😴':'сон','🤣':'хохот','😇':'ангел','🥺':'умоляет','😏':'ухмылка','👋':'привет',
    '✌️':'мир','🤞':'удача','👏':'аплодисменты','🐶':'собака','🐱':'кошка','🦊':'лиса',
    '🍕':'пицца','🍔':'бургер','🍟':'картошка','🍣':'суши','🍜':'лапша',
    '⚽':'футбол','🏀':'баскетбол','🎮':'игры','🎵':'музыка','🎨':'рисование',
}
let currentEmojiCategory = 'smileys'
let emojiSearchTimeout = null

function renderEmojiPicker() {
    const catBar = document.getElementById('emojiCategoryBar')
    if (!catBar) return
    if (catBar.children.length === 0) {
        const searchEl = document.getElementById('emojiSearch')
        if (searchEl && !searchEl._el) {
            searchEl._el = true
            searchEl.addEventListener('input', function() {
                clearTimeout(emojiSearchTimeout)
                emojiSearchTimeout = setTimeout(() => renderEmojiGrid(this.value.trim()), 200)
            })
        }
        EMOJI_CATEGORIES.forEach(cat => {
            const btn = document.createElement('button')
            btn.className = 'emoji-cat-btn' + (cat.id === currentEmojiCategory ? ' active' : '')
            btn.textContent = cat.icon
            btn.title = cat.label
            btn.onclick = () => {
                currentEmojiCategory = cat.id
                const s = document.getElementById('emojiSearch')
                if (s) s.value = ''
                renderEmojiGrid()
                catBar.querySelectorAll('.emoji-cat-btn').forEach(b => b.classList.remove('active'))
                btn.classList.add('active')
            }
            catBar.appendChild(btn)
        })
    }
    renderEmojiGrid()
}
function renderEmojiGrid(filter) {
    const grid  = document.getElementById('emojiGrid')
    const label = document.getElementById('emojiCategoryLabel')
    if (!grid) return
    let emojis
    if (filter && filter.length) {
        const q = filter.toLowerCase()
        const all = EMOJI_CATEGORIES.flatMap(c => c.emojis)
        emojis = all.filter(e => (EMOJI_NAMES[e] || '').includes(q))
        if (!emojis.length) {
            const cat = EMOJI_CATEGORIES.find(c => c.id === currentEmojiCategory)
            emojis = cat ? cat.emojis : []
        }
        if (label) label.textContent = emojis.length ? 'Найдено: ' + emojis.length : 'Ничего не найдено'
    } else {
        const cat = EMOJI_CATEGORIES.find(c => c.id === currentEmojiCategory)
        emojis = cat ? cat.emojis : []
        if (label) label.textContent = cat ? cat.label : ''
    }
    grid.innerHTML = ''
    const frag = document.createDocumentFragment()
    emojis.forEach(emoji => {
        const btn = document.createElement('button')
        btn.className = 'emoji-item'
        btn.textContent = emoji
        btn.addEventListener('click', () => insertEmoji(emoji))
        frag.appendChild(btn)
    })
    grid.appendChild(frag)
}
function insertEmoji(emoji) {
    const input = document.getElementById('text')
    if (!input) return
    const s = input.selectionStart ?? input.value.length
    const e = input.selectionEnd   ?? input.value.length
    input.value = input.value.slice(0, s) + emoji + input.value.slice(e)
    try { input.setSelectionRange(s + [...emoji].length, s + [...emoji].length) } catch(_) {}
    input.focus()
    if (navigator.vibrate) navigator.vibrate(10)
}

function cleanPhone(phone) {
    if (!phone) return ''
    return phone.toString().replace(/\s+/g, '').trim()
}

function showToast(message, duration = 3000) {
    const toast = document.getElementById('toast')
    toast.textContent = message
    toast.classList.add('show')
    
    setTimeout(() => {
        toast.classList.remove('show')
    }, duration)
}

function formatPhone(phone) {
    if (!phone) return 'Нет номера'
    const cleanNumber = phone.replace('+', '')
    if (cleanNumber.length === 11) {
        return cleanNumber.replace(/(\d{1})(\d{3})(\d{3})(\d{2})(\d{2})/, '+$1 ($2) $3-$4-$5')
    }
    return phone
}

function getAvatarLetter(name) {
    if (!name) return '?'
    if (name.startsWith('@') && name.length > 1) {
        return name[1].toUpperCase()
    }
    if (name.length > 0) {
        return name[0].toUpperCase()
    }
    return '?'
}

function escapeHtml(text) {
    const div = document.createElement('div')
    div.textContent = text
    return div.innerHTML
}

function hasClass(element, className) {
    if (!element) return false
    let current = element
    while (current) {
        if (current.classList && current.classList.contains(className)) {
            return true
        }
        current = current.parentElement
    }
    return false
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open')
}

function closeChat(event) {
    if (event) event.stopPropagation()
    currentChat = null
    document.getElementById('emptyChat').style.display = 'flex'
    document.getElementById('chatBlock').style.display = 'none'
    document.getElementById('sidebar').classList.add('open')
}

// ============= ФУНКЦИИ ДЛЯ СТАТУСОВ =============

function updateOnlineStatus() {
    document.querySelectorAll('.chatItem').forEach(item => {
        const phone = item.id.replace('chat-', '')
        const statusDot = item.querySelector('.chat-status')
        if (statusDot) {
            const isOnline = window.clients && window.clients[phone] === true
            statusDot.className = `chat-status ${isOnline ? '' : 'offline'}`
        }
    })
    
    if (currentChat) {
        const isOnline = window.clients && window.clients[currentChat] === true
        updateChatStatusText(currentChat, isOnline)
    }
}

function broadcastOnlineStatus(isOnline) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    
    const chatElements = document.querySelectorAll('.chatItem')
    chatElements.forEach(item => {
        const contactPhone = item.id.replace('chat-', '')
        ws.send(JSON.stringify({
            action: 'status',
            to: contactPhone,
            online: isOnline
        }))
    })
}

// ============= ФУНКЦИИ ДЛЯ ПРОВЕРКИ ПАРОЛЯ =============

function checkPasswordStrength(password) {
    const strength = {
        length: password.length >= 6,
        number: /\d/.test(password),
        letter: /[a-zA-Z]/.test(password)
    }
    
    const reqLength = document.getElementById('reqLength')
    const reqNumber = document.getElementById('reqNumber')
    const reqLetter = document.getElementById('reqLetter')
    const strengthBar = document.getElementById('strengthBar')
    const saveBtn = document.getElementById('savePasswordBtn')
    
    if (reqLength) {
        reqLength.innerHTML = (strength.length ? '✅' : '❌') + ' Минимум 6 символов'
        reqLength.className = 'requirement' + (strength.length ? ' met' : '')
    }
    
    if (reqNumber) {
        reqNumber.innerHTML = (strength.number ? '✅' : '❌') + ' Хотя бы одна цифра'
        reqNumber.className = 'requirement' + (strength.number ? ' met' : '')
    }
    
    if (reqLetter) {
        reqLetter.innerHTML = (strength.letter ? '✅' : '❌') + ' Хотя бы одна буква'
        reqLetter.className = 'requirement' + (strength.letter ? ' met' : '')
    }
    
    const score = Object.values(strength).filter(Boolean).length
    
    if (strengthBar) {
        strengthBar.className = 'strength-bar'
        if (score === 3) {
            strengthBar.classList.add('strong')
        } else if (score === 2) {
            strengthBar.classList.add('medium')
        } else if (score >= 1) {
            strengthBar.classList.add('weak')
        }
    }
    
    if (saveBtn) {
        saveBtn.disabled = !(strength.length && strength.number && strength.letter)
    }
}

// ============= ФУНКЦИИ ДЛЯ АВТОРИЗАЦИИ =============

function showRegisterForm() {
    document.getElementById('loginScreen').style.display = 'none'
    document.getElementById('registerScreen').style.display = 'flex'
}

function showLoginForm() {
    document.getElementById('registerScreen').style.display = 'none'
    document.getElementById('loginScreen').style.display = 'flex'
}

async function register() {
    const phone = document.getElementById('registerPhone').value.trim()
    const password = document.getElementById('registerPassword').value
    const confirm = document.getElementById('registerConfirm').value
    const username = document.getElementById('registerUsername').value.trim() || null
    const name = document.getElementById('registerName').value.trim() || null

    if (!phone) {
        showToast('Введите номер телефона')
        return
    }

    if (!password) {
        showToast('Введите пароль')
        return
    }

    if (password.length < 6) {
        showToast('Пароль должен быть не менее 6 символов')
        return
    }

    if (password !== confirm) {
        showToast('Пароли не совпадают')
        return
    }

    let cleanPhone = phone.replace(/[^0-9]/g, '')
    if (!cleanPhone.startsWith('+')) {
        if (cleanPhone.length === 11 && cleanPhone.startsWith('7')) {
            cleanPhone = '+' + cleanPhone
        } else if (cleanPhone.length === 10) {
            cleanPhone = '+7' + cleanPhone
        } else {
            cleanPhone = '+' + cleanPhone
        }
    }

    try {
        const res = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: cleanPhone,
                password: password,
                username: username,
                name: name
            })
        })

        const data = await res.json()

        if (!res.ok || data.error) {
            showToast(data.error || 'Ошибка регистрации')
            return
        }

        // Автологин
        showToast('Регистрация успешна!')
        const loginRes = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ phone: cleanPhone, password })
        })
        const loginData = await loginRes.json()
        if (loginRes.ok && !loginData.error) {
            currentUser = loginData.phone
            completeLogin()
        } else {
            showLoginForm()
            document.getElementById('loginPhone').value = cleanPhone
            showToast('Войдите в аккаунт')
        }

    } catch (error) {
        console.error('Register error:', error)
        showToast('Ошибка регистрации')
    }
}

async function login() {
    const phone = document.getElementById('loginPhone').value.trim()
    const password = document.getElementById('loginPassword').value

    if (!phone) {
        showToast('Введите номер телефона')
        return
    }

    if (!password) {
        showToast('Введите пароль')
        return
    }

    let cleanPhone = phone.replace(/[^0-9]/g, '')
    if (!cleanPhone.startsWith('+')) {
        if (cleanPhone.length === 11 && cleanPhone.startsWith('7')) {
            cleanPhone = '+' + cleanPhone
        } else if (cleanPhone.length === 10) {
            cleanPhone = '+7' + cleanPhone
        } else {
            cleanPhone = '+' + cleanPhone
        }
    }

    try {
        const res = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: cleanPhone,
                password: password
            })
        })

        const data = await res.json()

        if (!res.ok) {
            if (data.error === 'NO_PASSWORD_SET') {
                if (confirm('У этого аккаунта нет пароля. Хотите создать пароль?')) {
                    currentUser = cleanPhone
                    showPasswordSetupModal()
                }
                return
            }
            showToast(data.error || 'Ошибка входа')
            return
        }

        currentUser = data.phone
        completeLogin()

    } catch (error) {
        console.error('Login error:', error)
        showToast('Ошибка соединения с сервером')
    }
}

function showPasswordSetupModal() {
    document.getElementById('passwordSetupModal').classList.add('show')
}

async function savePasswordForExisting() {
    const password = document.getElementById('newPassword').value
    const confirm = document.getElementById('confirmPassword').value
    
    if (!password) {
        showToast('Введите пароль')
        return
    }
    
    if (password.length < 6) {
        showToast('Пароль должен быть не менее 6 символов')
        return
    }
    
    if (password !== confirm) {
        showToast('Пароли не совпадают')
        return
    }
    
    try {
        const res = await fetch('/set-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: currentUser,
                password: btoa(password)
            })
        })
        
        const data = await res.json()
        
        if (!res.ok) {
            showToast(data.error || 'Ошибка сохранения пароля')
            return
        }
        
        showToast('Пароль сохранен')
        closePasswordSetup()
        completeLogin()
        
    } catch (error) {
        console.error('Error saving password:', error)
        showToast('Ошибка сохранения пароля')
    }
}

function closePasswordSetup() {
    document.getElementById('passwordSetupModal').classList.remove('show')
}

function completeLogin() {
    loadTheme()
    loadChatThemesFromServer()
    document.getElementById('loginScreen').style.display = 'none'
    document.getElementById('app').style.display = 'flex'
    document.getElementById('sidebar').classList.add('open')

    document.getElementById('myPhone').innerText = formatPhone(currentUser)
    
    loadUserProfile()
    connect()
    loadChats()
    loadStickers() // Загружаем стикеры при входе
}

function openChangePassword() {
    document.getElementById('changePasswordModal').classList.add('show')
}

function closeChangePassword() {
    document.getElementById('changePasswordModal').classList.remove('show')
    document.getElementById('currentPassword').value = ''
    document.getElementById('newPasswordChange').value = ''
    document.getElementById('confirmPasswordChange').value = ''
}

async function changePassword() {
    const current = document.getElementById('currentPassword').value
    const newPass = document.getElementById('newPasswordChange').value
    const confirm = document.getElementById('confirmPasswordChange').value

    if (!current || !newPass) {
        showToast('Заполните все поля')
        return
    }

    if (newPass.length < 6) {
        showToast('Пароль должен быть не менее 6 символов')
        return
    }

    if (newPass !== confirm) {
        showToast('Новые пароли не совпадают')
        return
    }

    try {
        const res = await fetch('/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: currentUser,
                current_password: current,
                new_password: newPass
            })
        })

        const data = await res.json()

        if (data.error) {
            showToast(data.error)
            return
        }

        showToast('Пароль изменен')
        closeChangePassword()

    } catch (error) {
        console.error('Error changing password:', error)
        showToast('Ошибка смены пароля')
    }
}

// ============= ФУНКЦИИ ДЛЯ ПРОФИЛЯ =============

async function loadUserProfile() {
    try {
        const res = await fetch(`/user/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load profile')
        const data = await res.json()
        
        currentUserProfile = data
        
        const displayName = data.name || data.username || data.phone
        document.getElementById('myDisplayName').innerText = displayName
        
        const myAvatar = document.getElementById('myAvatarText')
        if (data.avatar) {
            myAvatar.innerHTML = `<img src="${data.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText='?'">`
        } else {
            myAvatar.innerText = '?'
        }
        
    } catch (error) {
        console.error('Error loading profile:', error)
    }
}

function openMyProfile() {
    showUserProfile(currentUser, true)
}

function openChatProfile() {
    if (currentChat) {
        showUserProfile(currentChat, false)
    }
}

async function showUserProfile(phone, isMyProfile = false) {
    try {
        const res = await fetch(`/user/${phone}`)
        if (!res.ok) throw new Error('Failed to load user')
        const user = await res.json()
        
        const settingsRes = await fetch(`/privacy-settings/${phone}`)
        const settings = await settingsRes.json()
        
        const modal = document.getElementById('profileModal')
        const profileView = document.getElementById('profileView')
        const profileEdit = document.getElementById('profileEdit')
        const modalActions = document.getElementById('modalActions')
        
        const displayName = user.name || user.username || user.phone
        
        const modalAvatar = document.getElementById('modalAvatarText')
        if (user.avatar && (isMyProfile || settings.avatar_privacy !== 'nobody')) {
            modalAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText='?'">`
        } else {
            modalAvatar.innerText = '?'
        }
        
        document.getElementById('modalName').innerText = user.name || 'Не указано'
        document.getElementById('modalUsername').innerText = user.username || 'Не установлен'
        document.getElementById('modalBio').innerText = user.bio || 'Не указано'
        
        if (isMyProfile || settings.phone_privacy === 'everyone') {
            document.getElementById('modalPhone').innerText = formatPhone(user.phone)
        } else {
            document.getElementById('modalPhone').innerText = 'Скрыто'
        }
        
        const isOnline = window.clients && window.clients[phone] === true
        document.getElementById('modalStatus').innerHTML = isOnline ? 
            '<span style="color: #4ade80;">● Онлайн</span>' : 
            '<span style="color: #f87171;">● Оффлайн</span>'
        
        modalActions.innerHTML = ''

        // Три точки — только для чужого профиля
        const profileMenuBtn = document.getElementById('profileMenuBtn')
        if (profileMenuBtn) profileMenuBtn.style.display = isMyProfile ? 'none' : 'flex'
        // Сохраняем телефон для действий из меню
        if (!isMyProfile) document.getElementById('profileModal')._profilePhone = phone
        
        if (isMyProfile) {
            profileView.style.display = 'block'
            profileEdit.style.display = 'none'
            
            const editBtn = document.createElement('button')
            editBtn.className = 'action-button primary'
            editBtn.innerHTML = '<i class="fas fa-pen"></i> Редактировать профиль'
            editBtn.onclick = () => {
                document.getElementById('editName').value = user.name || ''
                document.getElementById('editUsername').value = user.username || ''
                document.getElementById('editBio').value = user.bio || ''
                
                const previewAvatar = document.getElementById('previewAvatarText')
                if (user.avatar) {
                    previewAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
                } else {
                    previewAvatar.innerText = '?'
                }
                
                profileView.style.display = 'none'
                profileEdit.style.display = 'block'
            }
            modalActions.appendChild(editBtn)
            
        } else {
            profileView.style.display = 'block'
            profileEdit.style.display = 'none'
            
            const messageBtn = document.createElement('button')
            messageBtn.className = 'action-button primary'
            messageBtn.innerHTML = '<i class="fas fa-comment"></i> Написать сообщение'
            messageBtn.onclick = () => {
                closeModal()
                openChat(phone, displayName)
            }
            modalActions.appendChild(messageBtn)
        }
        
        modal.classList.add('show')
        
    } catch (error) {
        console.error('Error loading user profile:', error)
        showToast('Ошибка загрузки профиля')
    }
}

async function saveProfile() {
    const username = document.getElementById('editUsername').value.trim()
    const name = document.getElementById('editName').value.trim()
    const bio = document.getElementById('editBio').value.trim()
    
    if (!username) {
        showToast('Введите username')
        return
    }
    
    if (!username.startsWith('@')) {
        showToast('Username должен начинаться с @')
        return
    }
    
    if (cropper) {
        await saveCroppedAvatar()
    }
    
    try {
        const res = await fetch(`/user/${currentUser}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, name, bio })
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        showToast('Профиль обновлен')
        closeModal()
        
        await loadUserProfile()
        loadChats()
        
    } catch (error) {
        console.error('Error saving profile:', error)
        showToast('Ошибка сохранения')
    }
}

function closeModal() {
    document.getElementById('profileModal').classList.remove('show')
    document.getElementById('profileView').style.display = 'block'
    document.getElementById('profileEdit').style.display = 'none'
}

function cancelEdit() {
    document.getElementById('profileView').style.display = 'block'
    document.getElementById('profileEdit').style.display = 'none'
}

// ============= ФУНКЦИИ ДЛЯ РЕДАКТОРА АВАТАРА =============

document.getElementById('avatarInput')?.addEventListener('change', function(e) {
    const file = e.target.files[0]
    if (file) {
        if (file.size > 5 * 1024 * 1024) {
            showToast('Файл слишком большой (макс 5MB)')
            return
        }
        
        if (!file.type.startsWith('image/')) {
            showToast('Пожалуйста, выберите изображение')
            return
        }
        
        const reader = new FileReader()
        reader.onload = function(e) {
            document.getElementById('previewAvatarText').innerHTML = 
                `<img src="${e.target.result}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
            
            openAvatarEditor(e.target.result)
        }
        reader.readAsDataURL(file)
    }
})

function openAvatarEditor(imageUrl) {
    const modal = document.getElementById('avatarEditorModal')
    const image = document.getElementById('avatarImage')
    
    image.src = imageUrl
    modal.classList.add('show')
    
    image.onload = function() {
        if (cropper) {
            cropper.destroy()
        }
        
        cropper = new Cropper(image, {
            aspectRatio: 1 / 1,
            viewMode: 1,
            dragMode: 'move',
            autoCropArea: 1,
            cropBoxMovable: true,
            cropBoxResizable: true,
            toggleDragModeOnDblclick: false,
            minCropBoxWidth: 100,
            minCropBoxHeight: 100,
            zoomable: true,
            scalable: true,
            rotatable: true
        })
        
        updateZoomLevel()
    }
}

function closeAvatarEditor() {
    const modal = document.getElementById('avatarEditorModal')
    modal.classList.remove('show')
    
    if (cropper) {
        cropper.destroy()
        cropper = null
    }
    
    document.getElementById('avatarInput').value = ''
}

function zoomIn() {
    if (cropper) {
        cropper.zoom(0.1)
        updateZoomLevel()
    }
}

function zoomOut() {
    if (cropper) {
        cropper.zoom(-0.1)
        updateZoomLevel()
    }
}

function rotateLeft() {
    if (cropper) {
        cropper.rotate(-90)
    }
}

function rotateRight() {
    if (cropper) {
        cropper.rotate(90)
    }
}

function updateZoomLevel() {
    if (cropper) {
        const zoom = cropper.getZoom()
        const percent = Math.round(zoom * 100)
        document.getElementById('zoomLevel').textContent = percent + '%'
    }
}

async function saveCroppedAvatar() {
    if (!cropper || !currentUser) return
    
    showToast('Обработка изображения...')
    
    try {
        const canvas = cropper.getCroppedCanvas({
            width: 512,
            height: 512,
            imageSmoothingEnabled: true,
            imageSmoothingQuality: 'high'
        })
        
        const blob = await new Promise(resolve => {
            canvas.toBlob(resolve, 'image/jpeg', 0.9)
        })
        
        const formData = new FormData()
        formData.append('file', blob, 'avatar.jpg')
        
        const res = await fetch(`/upload-avatar/${currentUser}`, {
            method: 'POST',
            body: formData
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        showToast('Аватар загружен')
        
        closeAvatarEditor()
        
        await loadUserProfile()
        loadChats()
        
    } catch (error) {
        console.error('Error uploading avatar:', error)
        showToast('Ошибка загрузки')
    }
}

async function removeAvatar() {
    if (!confirm('Удалить аватар?')) return
    
    try {
        const res = await fetch(`/remove-avatar/${currentUser}`, {
            method: 'DELETE'
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        showToast('Аватар удален')
        
        document.getElementById('previewAvatarText').innerText = '?'
        document.getElementById('avatarInput').value = ''
        
        closeAvatarEditor()
        
        await loadUserProfile()
        loadChats()
        
    } catch (error) {
        console.error('Error removing avatar:', error)
        showToast('Ошибка удаления')
    }
}

// ============= СТИКЕРЫ =============

// Загрузить сохраненные стикеры
async function loadStickers() {
    try {
        const res = await fetch(`/api/stickers/${encodeURIComponent(currentUser)}`)
        if (res.ok) {
            const data = await res.json()
            const raw = data.stickers || []
            console.log(`[stickers] total=${raw.length}, first=`, raw[0])
            // Нормализуем: принимаем [{id,url}] и [url] и [string]
            userStickers = raw.map(s =>
                typeof s === 'string' ? { id: null, url: s } : { id: s.id || null, url: s.url || s.sticker_url || s }
            )
            console.log(`[stickers] normalized first=`, userStickers[0])
            renderStickers()
        } else {
            console.error('[stickers] fetch failed', res.status)
        }
    } catch (error) {
        console.error('[stickers] Error loading stickers:', error)
    }
}

// Переключение модального окна стикеров
function toggleStickerModal() {
    const modal = document.getElementById('stickerModal')
    const btn = document.getElementById('stickerBtn')
    
    if (modal.classList.contains('show')) {
        closeStickerModal()
    } else {
        openStickerModal()
    }
}

// Открыть модальное окно стикеров
function openStickerModal() {
    const modal = document.getElementById('stickerModal')
    const btn = document.getElementById('stickerBtn')
    if (!modal) return
    loadStickers()
    const inputArea = document.querySelector('.input-area')
    if (inputArea && btn) {
        const ir = inputArea.getBoundingClientRect()
        const br = btn.getBoundingClientRect()
        modal.style.bottom = (window.innerHeight - ir.top + 8) + 'px'
        if (window.innerWidth <= 768) {
            modal.style.right = '8px'; modal.style.left = '8px'
        } else {
            modal.style.right = Math.max(8, window.innerWidth - br.right - 8) + 'px'
            modal.style.left = ''
        }
    }
    modal.classList.add('show')
    if (btn) btn.classList.add('active')
    requestAnimationFrame(() => requestAnimationFrame(() => renderEmojiPicker()))
}

// Закрыть модальное окно стикеров
function closeStickerModal() {
    console.log('Closing sticker modal')
    const modal = document.getElementById('stickerModal')
    const btn = document.getElementById('stickerBtn')
    
    if (modal) {
        modal.classList.remove('show')
    }
    
    if (btn) {
        btn.classList.remove('active')
    }
}

// Переключение вкладок стикеров
function switchStickerTab(tab) {
    document.querySelectorAll('.sticker-tab-btn').forEach(b => b.classList.remove('active'))
    document.querySelectorAll('.sticker-tab-content').forEach(c => c.classList.remove('active'))
    const map = { emoji:['tabEmojiBtn','emojiTab'], my:['tabMyBtn','myStickersTab'],
                  popular:['tabPopularBtn','popularStickersTab'], upload:['tabUploadBtn','uploadStickersTab'] }
    const t = map[tab]; if (!t) return
    document.getElementById(t[0])?.classList.add('active')
    document.getElementById(t[1])?.classList.add('active')
    if (tab === 'emoji') requestAnimationFrame(() => renderEmojiPicker())
}

// Отображение стикеров
function renderStickers() {
    const myStickersDiv = document.getElementById('myStickers')
    const popularStickersDiv = document.getElementById('popularStickers')
    const emptyMyStickers = document.getElementById('emptyMyStickers')
    
    if (myStickersDiv) {
        myStickersDiv.innerHTML = ''
        
        if (userStickers.length === 0) {
            if (emptyMyStickers) {
                emptyMyStickers.style.display = 'flex'
                emptyMyStickers.innerHTML = `
                    <span>Нет стикеров — добавьте через вкладку «+»</span>
                    <button onclick="cleanBrokenStickers()" style="margin-top:8px;padding:6px 12px;background:var(--accent);color:white;border:none;border-radius:8px;cursor:pointer;font-size:12px;">
                        🗑 Очистить старые записи
                    </button>`
            }
        } else {
            if (emptyMyStickers) emptyMyStickers.style.display = 'none'
            userStickers.forEach((sticker, idx) => {
                const url = typeof sticker === 'string' ? sticker : sticker.url
                const id  = typeof sticker === 'object' ? sticker.id : null
                const div = document.createElement('div')
                div.className = 'sticker-item'
                div.setAttribute('data-sticker-url', url)
                div.onclick = () => sendSticker(url)

                const img = document.createElement('img')
                img.src = url
                img.alt = 'sticker'
                img.loading = 'lazy'
                img.onerror = () => { console.warn('[sticker] failed to load:', url); img.style.opacity='0.3' }
                div.appendChild(img)

                // Кнопка удаления
                if (id) {
                    const del = document.createElement('button')
                    del.className = 'sticker-delete-btn'
                    del.textContent = '✕'
                    del.onclick = e => { e.stopPropagation(); deleteSticker(id, div) }
                    div.appendChild(del)
                }

                myStickersDiv.appendChild(div)
            })
        }
    }
    
    if (popularStickersDiv) {
        popularStickersDiv.innerHTML = ''
        popularStickers.forEach(sticker => {
            const div = document.createElement('div')
            div.className = 'sticker-item'
            div.setAttribute('data-sticker-url', sticker)
            div.onclick = () => sendSticker(sticker)
            
            const img = document.createElement('img')
            img.src = sticker
            img.alt = 'sticker'
            div.appendChild(img)
            
            popularStickersDiv.appendChild(div)
        })
    }
}

// Отправить стикер
function sendSticker(stickerUrl) {
    if (!currentChat) {
        showToast('Выберите чат')
        return
    }
    
    ws.send(JSON.stringify({
        action: 'send',
        to: currentChat,
        text: `[STICKER]${stickerUrl}[/STICKER]`
    }))
    // НЕ вызываем addStickerMessage — придёт через message_sent
    closeStickerModal()
}

// Добавить сообщение со стикером
function addStickerMessage(user, stickerUrl) {
    const messagesDiv = document.getElementById('messages')
    const div = document.createElement('div')
    
    div.className = 'message sticker ' + (user === currentUser ? 'me' : 'other')
    
    const img = document.createElement('img')
    img.src = stickerUrl
    img.alt = 'sticker'
    div.appendChild(img)
    
    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

function addMessage(user, text, messageId = null, isRead = false) {
    const messagesDiv = document.getElementById('messages')
    const div = document.createElement('div')
    const isMe = user === currentUser

    const stickerMatch = text.match(/\[STICKER\](.*?)\[\/STICKER\]/)
    const voiceMatch   = text.match(/\[VOICE(?::(\d+))?\](.*?)\[\/VOICE\]/)
    const videoMatch   = text.match(/\[VIDEO(?::(\d+))?\](.*?)\[\/VIDEO\]/)
    const musicMatch   = text.match(/\[MUSIC\](.+?)\[\/MUSIC\]/)

    if (videoMatch) {
        div.className = 'message me-video ' + (isMe ? 'me' : 'other')
        if (messageId) div.dataset.messageId = messageId
        const vidUrl = videoMatch[2]
        const vidDuration = parseInt(videoMatch[1] || '0')
        const player = createVideoPlayer(vidUrl, isMe, vidDuration)
        div.appendChild(player)
        if (isMe) {
            const ticks = document.createElement('span')
            ticks.className = `msg-ticks sticker-ticks${isRead ? ' read' : ''}`
            ticks.innerHTML = '<i class="fas fa-check"></i><i class="fas fa-check tick-second"></i>'
            div.appendChild(ticks)
        }
    } else if (musicMatch) {
        div.className = 'message music-message ' + (isMe ? 'me' : 'other')
        if (messageId) div.dataset.messageId = messageId
        try {
            const trackData = JSON.parse(musicMatch[1])
            const card = createMusicCard(trackData, isMe)
            div.appendChild(card)
        } catch(e) {
            div.textContent = '🎵 Музыкальный трек'
        }
        if (isMe) {
            const ticks = document.createElement('span')
            ticks.className = `msg-ticks sticker-ticks${isRead ? ' read' : ''}`
            ticks.innerHTML = '<i class="fas fa-check"></i><i class="fas fa-check tick-second"></i>'
            div.appendChild(ticks)
        }
    } else if (voiceMatch) {
        div.className = 'message voice-message ' + (isMe ? 'me' : 'other')
        if (messageId) div.dataset.messageId = messageId
        const duration = parseInt(voiceMatch[1] || '0')
        let voiceUrl = voiceMatch[2]
        // Нормализуем старые пути /voice/123 → /api/voice/123
        if (voiceUrl.match(/^\/voice\/\d+$/)) voiceUrl = '/api' + voiceUrl
        const player = createVoicePlayer(voiceUrl, isMe, duration)
        div.appendChild(player)
        if (isMe) {
            const ticks = document.createElement('span')
            ticks.className = `msg-ticks voice-ticks${isRead ? ' read' : ''}`
            ticks.innerHTML = '<i class="fas fa-check"></i><i class="fas fa-check tick-second"></i>'
            div.appendChild(ticks)
        }
    } else if (stickerMatch) {
        div.className = 'message sticker ' + (isMe ? 'me' : 'other')
        if (messageId) div.dataset.messageId = messageId

        const img = document.createElement('img')
        img.src = stickerMatch[1]
        img.alt = 'sticker'
        div.appendChild(img)

        // Галочки поверх стикера (только для своих)
        if (isMe) {
            const ticks = document.createElement('span')
            ticks.className = `msg-ticks sticker-ticks${isRead ? ' read' : ''}`
            ticks.innerHTML = '<i class="fas fa-check"></i><i class="fas fa-check tick-second"></i>'
            div.appendChild(ticks)
        }

        // Кнопка реакции
        if (messageId) {
            const reBtn = document.createElement('button')
            reBtn.className = 'add-reaction-btn'
            reBtn.textContent = '😊'
            reBtn.onclick = (e) => showReactionsPanel(e, messageId)
            div.appendChild(reBtn)
        }
    } else {
        div.className = 'message ' + (isMe ? 'me' : 'other')
        if (messageId) div.dataset.messageId = messageId

        const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
        // isRead=null → отправляется (1 галочка), isRead=false → доставлено (2 серых), isRead=true → прочитано (2 синих)
        const ticks = isMe
            ? `<span class="msg-ticks${isRead === true ? ' read' : ''}">
                <i class="fas fa-check tick-first"></i><i class="fas fa-check tick-second" style="${isRead === null ? 'display:none' : ''}"></i>
               </span>`
            : ''

        // Пересланное сообщение
        const fwdMatch = text.match(/^\[FWD:(.+?)\]([\s\S]*?)\[\/FWD\]$/)
        let bodyHtml
        if (fwdMatch) {
            const fwdMeta = fwdMatch[1]  // "имя|телефон" или просто "имя"
            const pipeIdx = fwdMeta.lastIndexOf('|')
            const fwdName  = pipeIdx >= 0 ? fwdMeta.slice(0, pipeIdx) : fwdMeta
            const fwdPhone = pipeIdx >= 0 ? fwdMeta.slice(pipeIdx + 1) : null
            const nameHtml = fwdPhone
                ? `<span class="fwd-name-link" onclick="showUserProfile('${escapeHtml(fwdPhone)}',false)" title="Открыть профиль">${escapeHtml(fwdName)}</span>`
                : `<b>${escapeHtml(fwdName)}</b>`
            bodyHtml = `<div class="fwd-header"><i class="fas fa-share"></i> Переслано от ${nameHtml}</div>
                        <div class="message-text">${escapeHtml(fwdMatch[2])}</div>`
        } else {
            bodyHtml = `<div class="message-text">${escapeHtml(text)}</div>`
        }

        div.innerHTML = `${bodyHtml}
            <div class="message-meta">
                <span class="message-time">${time}</span>${ticks}
            </div>
            <button class="add-reaction-btn" onclick="showReactionsPanel(event,${messageId})">😊</button>`
    }

    // Контекстное меню — для всех сообщений включая стикеры
    if (messageId) {
        const ctxHandler = (e) => {
            e.preventDefault()
            const msgText = stickerMatch
                ? `[STICKER]${stickerMatch[1]}[/STICKER]`
                : voiceMatch
                ? text  // голосовые пересылаем как есть
                : (div.querySelector('.message-text')?.innerText || '')
            showContextMenu(e, 'message', { messageId, element: div, text: msgText, sender: user })
        }
        div.addEventListener('contextmenu', ctxHandler)
        // Долгое нажатие для мобильных
        let lpTimer = null
        div.addEventListener('touchstart', (te) => {
            const touch = te.touches[0]
            const startX = touch ? touch.pageX : 0
            const startY = touch ? touch.pageY : 0
            lpTimer = setTimeout(() => {
                if (window.navigator.vibrate) window.navigator.vibrate(40)
                const fakeE = {
                    preventDefault() {}, stopPropagation() {},
                    pageX: startX, pageY: startY,
                    touches: [{ pageX: startX, pageY: startY }]
                }
                ctxHandler(fakeE)
            }, 500)
        }, { passive: true })
        div.addEventListener('touchend',   () => clearTimeout(lpTimer))
        div.addEventListener('touchmove',  () => clearTimeout(lpTimer))
    }

    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
    if (messageId) loadMessageReactions(messageId)
}

// Обработка загрузки стикеров
document.getElementById('stickerFiles')?.addEventListener('change', handleStickerFiles)

function handleStickerFiles(event) {
    const files = Array.from(event.target.files)
    const preview = document.getElementById('stickerPreview')
    preview.innerHTML = ''
    
    files.forEach((file, index) => {
        if (file.type.startsWith('image/')) {
            const reader = new FileReader()
            reader.onload = (e) => {
                const div = document.createElement('div')
                div.className = 'preview-item'
                div.innerHTML = `
                    <img src="${e.target.result}" alt="preview">
                    <button class="remove-btn" onclick="this.parentElement.remove()">✕</button>
                `
                preview.appendChild(div)
            }
            reader.readAsDataURL(file)
        }
    })
}

async function importTgStickers() {
    const urlInput = document.getElementById('tgStickerUrl')
    const btn      = document.getElementById('tgImportBtn')
    const status   = document.getElementById('tgImportStatus')
    const url      = urlInput?.value.trim()

    if (!url) { showToast('Вставьте ссылку на пак'); return }
    if (!url.includes('t.me')) { showToast('Неверная ссылка. Пример: t.me/addstickers/PackName'); return }

    // UI: загрузка
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>' }
    if (status) { status.style.display = 'flex'; status.className = 'tg-import-status loading'; status.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Загружаю стикеры...' }

    try {
        const res = await fetch(`/api/import-sticker-pack/${encodeURIComponent(currentUser)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pack_url: url, phone: currentUser })
        })
        const data = await res.json()

        if (!res.ok || data.error) {
            if (status) { status.className = 'tg-import-status error'; status.innerHTML = `<i class="fas fa-xmark"></i> ${data.error || 'Ошибка'}` }
            return
        }

        if (status) { status.className = 'tg-import-status success'; status.innerHTML = `<i class="fas fa-check"></i> Загружено ${data.saved} стикеров из «${data.pack_title}»` }
        if (urlInput) urlInput.value = ''

        // Переключаемся на вкладку «Мои» и обновляем
        await loadStickers()
        switchStickerTab('my')

    } catch (e) {
        if (status) { status.className = 'tg-import-status error'; status.innerHTML = '<i class="fas fa-xmark"></i> Нет соединения с сервером' }
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-download"></i>' }
    }
}

async function uploadStickers() {
    const files = document.getElementById('stickerFiles').files
    if (files.length === 0) {
        showToast('Выберите файлы для загрузки')
        return
    }
    
    const formData = new FormData()
    for (let i = 0; i < files.length; i++) {
        formData.append('stickers', files[i])
    }
    
    try {
        showToast('Загрузка стикеров...')
        
        const res = await fetch(`/api/upload-stickers/${encodeURIComponent(currentUser)}`, {
            method: 'POST',
            body: formData
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        showToast('Стикеры загружены')
        
        // Очищаем предпросмотр
        document.getElementById('stickerPreview').innerHTML = ''
        document.getElementById('stickerFiles').value = ''
        
        // Перезагружаем стикеры
        await loadStickers()
        
        // Переключаемся на вкладку "Мои стикеры"
        switchStickerTab('my')
        
    } catch (error) {
        console.error('Error uploading stickers:', error)
        showToast('Ошибка загрузки стикеров')
    }
}



// ============= ИМПОРТ СТИКЕРОВ ИЗ TELEGRAM =============

async function previewTgPack() {
    const input = document.getElementById('tgPackUrl')
    const url   = input?.value.trim()
    if (!url) { showToast('Вставьте ссылку на пак'); return }

    // Принимаем любой формат:
    // https://t.me/addstickers/PackName
    // t.me/addstickers/PackName
    // просто PackName
    let packName = url
    const linkMatch = url.match(/t\.me\/addstickers\/([\w]+)/i)
    if (linkMatch) {
        packName = linkMatch[1]
    } else if (/^[\w]+$/.test(url)) {
        packName = url
    } else {
        showToast('Неверная ссылка. Формат: t.me/addstickers/ИмяПака')
        return
    }

    const btn = document.querySelector('.tg-import-btn')
    if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>'; btn.disabled = true }
    document.getElementById('tgPackPreview').style.display = 'none'

    // Показываем прогресс-бар сразу
    const progress = document.getElementById('tgImportProgress')
    const fill     = document.getElementById('tgProgressFill')
    const text     = document.getElementById('tgProgressText')
    progress.style.display = 'block'
    fill.style.transition = 'none'; fill.style.width = '5%'
    text.textContent = 'Получаю стикеры из Telegram...'
    document.getElementById('tgImportBtn').style.display = 'none'

    // Анимируем прогресс пока идёт загрузка
    let fake = 5
    const fakeTimer = setInterval(() => {
        fake = Math.min(fake + 3, 85)
        fill.style.transition = 'width 0.8s'
        fill.style.width = fake + '%'
    }, 800)

    try {
        const res  = await fetch(`/api/import-sticker-pack/${encodeURIComponent(currentUser)}`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ url: packName })
        })
        const data = await res.json()

        clearInterval(fakeTimer)
        fill.style.transition = 'width 0.4s'
        fill.style.width = '100%'

        if (!res.ok || data.error) {
            const errMsg = data.error || 'Ошибка импорта'
            console.error('Import error detail:', data.detail || errMsg)
            text.textContent = '❌ ' + errMsg
            showToast(data.error || 'Ошибка импорта')
            document.getElementById('tgImportBtn').style.display = 'block'
            document.getElementById('tgImportBtn').disabled = false
            document.getElementById('tgImportBtn').innerHTML = '<i class="fas fa-download"></i> Добавить все стикеры'
            return
        }

        text.textContent = `✅ Добавлено ${data.added} стикеров из «${data.title}»!`
        showToast(`Добавлено ${data.added} стикеров из «${data.title}»`)
        if (input) input.value = ''

        await loadStickers()
        setTimeout(() => {
            cancelTgImport()
            switchStickerTab('my')
        }, 1800)

    } catch (e) {
        clearInterval(fakeTimer)
        text.textContent = '❌ Нет соединения с сервером'
        showToast('Ошибка соединения')
        document.getElementById('tgImportBtn').style.display = 'block'
    } finally {
        if (btn) { btn.innerHTML = '<i class="fas fa-search"></i>'; btn.disabled = false }
    }
}

// Кнопка «Добавить все» — просто повторяет previewTgPack (импорт уже произошёл)
function importTgPack() { /* импорт уже выполнен в previewTgPack */ }

function cancelTgImport() {
    document.getElementById('tgPackPreview').style.display = 'none'
    document.getElementById('tgImportProgress').style.display = 'none'
    const input = document.getElementById('tgPackUrl')
    if (input) input.value = ''
}

const uploadArea = document.getElementById('stickerUploadArea')
if (uploadArea) {
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault()
        uploadArea.classList.add('dragover')
    })
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover')
    })
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault()
        uploadArea.classList.remove('dragover')
        
        const files = Array.from(e.dataTransfer.files)
        document.getElementById('stickerFiles').files = e.dataTransfer.files
        handleStickerFiles({ target: { files } })
    })
}


// ============= ГОЛОСОВЫЕ СООБЩЕНИЯ =============

let mediaRecorder = null
let voiceChunks = []
let voiceStartTime = null
let voiceTimer = null
let voiceCancelled = false
let voiceTouchStartX = 0
let voiceMode = localStorage.getItem('voiceMode') || 'tap'  // 'tap' | 'hold'
let voiceTapActive = false  // для режима tap

// ── Настройки камеры ──────────────────────────────────────────
function loadCameraSettings() {
    const facing  = localStorage.getItem('cameraFacing')  || 'user'
    const quality = localStorage.getItem('cameraQuality') || '480'
    const maxDur  = localStorage.getItem('videoMaxDur')   || '60'

    const f = document.getElementById('cameraFacing')
    const q = document.getElementById('cameraQuality')
    const d = document.getElementById('videoMaxDur')
    if (f) f.value = facing
    if (q) q.value = quality
    if (d) d.value = maxDur

    // Применяем к глобальной переменной длительности
    videoMaxDuration = parseInt(maxDur)
}

function saveCameraSettings() {
    const facing  = document.getElementById('cameraFacing')?.value  || 'user'
    const quality = document.getElementById('cameraQuality')?.value || '480'
    const maxDur  = document.getElementById('videoMaxDur')?.value   || '60'

    localStorage.setItem('cameraFacing',  facing)
    localStorage.setItem('cameraQuality', quality)
    localStorage.setItem('videoMaxDur',   maxDur)

    videoMaxDuration = parseInt(maxDur)
    showToast('Настройки камеры сохранены')
}

function getCameraConstraints() {
    const facing  = localStorage.getItem('cameraFacing')  || 'user'
    const quality = parseInt(localStorage.getItem('cameraQuality') || '480')
    return {
        video: { facingMode: facing, width: { ideal: quality }, height: { ideal: quality } },
        audio: true
    }
}

function saveVoiceMode() {
    const sel = document.getElementById('voiceMode')
    if (!sel) return
    voiceMode = sel.value
    localStorage.setItem('voiceMode', voiceMode)
    updateVoiceBtnBehavior()
    showToast(voiceMode === 'hold' ? 'Режим: зажать кнопку' : 'Режим: нажать дважды')
}

function loadVoiceModeSetting() {
    const sel = document.getElementById('voiceMode')
    if (sel) sel.value = voiceMode
    updateVoiceBtnBehavior()
}

function updateVoiceBtnBehavior() {
    const btn = document.getElementById('voiceBtn')
    if (!btn) return

    // Сбрасываем все обработчики
    btn.onmousedown = btn.onmouseup = btn.onmouseleave = null
    btn.ontouchstart = btn.ontouchend = btn.ontouchcancel = null
    btn.onclick = null

    // Используем Pointer Events — работают одинаково на мышке и тачскрине
    // Удаляем старые листенеры через замену элемента
    const newBtn = btn.cloneNode(true)
    btn.parentNode.replaceChild(newBtn, btn)
    const b = newBtn

    if (voiceMode === 'hold') {
        b.title = 'Зажать и держать для записи'
        b.style.cursor = 'grab'
        b.addEventListener('pointerdown', (e) => {
            e.preventDefault()
            b.setPointerCapture(e.pointerId)
            startVoiceRecord(e)
        })
        b.addEventListener('pointerup', (e) => {
            e.preventDefault()
            stopVoiceRecord(e)
        })
        b.addEventListener('pointercancel', () => cancelVoiceRecord())
    } else {
        b.title = 'Нажать для начала/конца записи'
        b.style.cursor = 'pointer'
        b.addEventListener('pointerdown', (e) => {
            e.preventDefault()
            b.setPointerCapture(e.pointerId)
        })
        b.addEventListener('pointerup', (e) => {
            e.preventDefault()
            // Проверяем что pointer был на кнопке при отпускании
            const rect = b.getBoundingClientRect()
            const inside = e.clientX >= rect.left && e.clientX <= rect.right
                        && e.clientY >= rect.top  && e.clientY <= rect.bottom
            if (!inside) return
            if (!voiceTapActive) {
                voiceTapActive = true
                startVoiceRecord(null)
            } else {
                voiceTapActive = false
                commitVoice()
            }
        })
    }
}

// ── Голосовая запись ──────────────────────────────────────────────────
let voiceAnalyser = null
let voiceWaveAnim = null
let voiceStream   = null
let voiceAudioCtx = null

function showRecordArea() {
    const inputArea  = document.getElementById('inputArea')
    const recordArea = document.getElementById('voiceRecordArea')
    if (!inputArea || !recordArea) return

    // Строим бары волны один раз
    const waveEl = document.getElementById('voiceRecordWave')
    if (waveEl && !waveEl.children.length) {
        for (let i = 0; i < 28; i++) {
            const b = document.createElement('div')
            b.className = 'vrec-bar'
            waveEl.appendChild(b)
        }
    }

    inputArea.classList.add('input-hidden')
    recordArea.classList.add('record-visible')
}

function hideRecordArea() {
    const inputArea  = document.getElementById('inputArea')
    const recordArea = document.getElementById('voiceRecordArea')
    if (!inputArea || !recordArea) return
    recordArea.classList.remove('record-visible')
    inputArea.classList.remove('input-hidden')
}

async function startVoiceRecord(e) {
    if (e) e.preventDefault()
    if (!currentChat) { showToast('Выберите чат'); return }
    if (mediaRecorder && mediaRecorder.state !== 'inactive') return

    try {
        voiceStream = await navigator.mediaDevices.getUserMedia({ audio: true })
        voiceChunks = []
        voiceCancelled = false
        voiceTouchStartX = e?.touches?.[0]?.clientX ?? 0

        // Выбираем формат с максимальной совместимостью
        // mp4/aac работает в Safari, webm/opus в Chrome/Firefox
        const mimeTypes = [
            'audio/mp4;codecs=mp4a.40.2',  // Safari iOS/macOS
            'audio/mp4',                    // Safari fallback
            'audio/webm;codecs=opus',       // Chrome/Firefox
            'audio/webm',                   // Chrome fallback
            'audio/ogg;codecs=opus',        // Firefox
            '',                             // браузер выберет сам
        ]
        const mimeType = mimeTypes.find(m => !m || MediaRecorder.isTypeSupported(m)) || ''

        mediaRecorder = new MediaRecorder(voiceStream, mimeType ? { mimeType } : {})
        mediaRecorder.ondataavailable = ev => { if (ev.data.size > 0) voiceChunks.push(ev.data) }
        mediaRecorder.onstop = () => {
            if (voiceStream) { voiceStream.getTracks().forEach(t => t.stop()); voiceStream = null }
            stopWaveAnimation()
            voiceTapActive = false
            const vBtn = document.getElementById('voiceBtn')
            if (vBtn) {
                vBtn.classList.remove('recording')
                vBtn.querySelector('i').className = 'fas fa-microphone'
            }
            if (!voiceCancelled) sendVoiceMessage()
        }
        mediaRecorder.start(100)

        // Web Audio API — реальная амплитуда
        try {
            // Закрываем предыдущий контекст если есть
            if (voiceAudioCtx) { voiceAudioCtx.close(); voiceAudioCtx = null }
            voiceAudioCtx = new AudioContext()
            const source = voiceAudioCtx.createMediaStreamSource(voiceStream)
            voiceAnalyser = voiceAudioCtx.createAnalyser()
            voiceAnalyser.fftSize = 128
            source.connect(voiceAnalyser)
        } catch (_) {}

        voiceStartTime = Date.now()
        showRecordArea()
        // Меняем иконку микрофона на стоп в tap-режиме
        const vBtn = document.getElementById('voiceBtn')
        if (vBtn) {
            vBtn.classList.add('recording')
            vBtn.querySelector('i').className = voiceMode === 'tap'
                ? 'fas fa-stop'
                : 'fas fa-microphone'
        }
        if (navigator.vibrate) navigator.vibrate(40)
        startWaveAnimation()

        voiceTimer = setInterval(() => {
            const sec = Math.floor((Date.now() - voiceStartTime) / 1000)
            const m = Math.floor(sec / 60), s = sec % 60
            const el = document.getElementById('voiceRecTime')
            if (el) el.textContent = `${m}:${s.toString().padStart(2,'0')}`
        }, 500)

    } catch (err) {
        showToast('Нет доступа к микрофону')
        console.error('Voice record error:', err)
    }
}

// Для режима hold — отпускание кнопки
function stopVoiceRecord(e) {
    if (!mediaRecorder || mediaRecorder.state === 'inactive') return
    if (e) e.preventDefault()
    const endX = e?.changedTouches?.[0]?.clientX ?? voiceTouchStartX
    if (voiceTouchStartX - endX > 80) { cancelVoiceRecord(); return }
    const dur = Date.now() - voiceStartTime
    if (dur < 500) { cancelVoiceRecord(); showToast('Слишком короткое'); return }
    clearInterval(voiceTimer)
    // Запрашиваем финальный чанк перед остановкой
    mediaRecorder.requestData()
    setTimeout(() => mediaRecorder.stop(), 50)
}

// Кнопка ✈ в строке записи (режим tap или явная отправка)
function commitVoice() {
    if (!mediaRecorder || mediaRecorder.state === 'inactive') return
    const dur = Date.now() - voiceStartTime
    if (dur < 500) { cancelVoiceRecord(); showToast('Слишком короткое'); return }
    clearInterval(voiceTimer)
    mediaRecorder.requestData()
    setTimeout(() => mediaRecorder.stop(), 50)
}

function cancelVoiceRecord() {
    voiceCancelled = true
    voiceTapActive = false
    clearInterval(voiceTimer)
    if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop()
    else {
        if (voiceStream) { voiceStream.getTracks().forEach(t => t.stop()); voiceStream = null }
        stopWaveAnimation()
    }
    hideRecordArea()
    voiceChunks = []
    // Восстанавливаем иконку кнопки
    const vBtn = document.getElementById('voiceBtn')
    if (vBtn) {
        vBtn.classList.remove('recording')
        vBtn.querySelector('i').className = 'fas fa-microphone'
    }
    if (navigator.vibrate) navigator.vibrate([20, 20])
}

function startWaveAnimation() {
    const waveEl = document.getElementById('voiceRecordWave')
    if (!waveEl) return
    const bars = waveEl.querySelectorAll('.vrec-bar')
    const dataArr = voiceAnalyser ? new Uint8Array(voiceAnalyser.frequencyBinCount) : null

    function draw() {
        voiceWaveAnim = requestAnimationFrame(draw)
        bars.forEach((b, i) => {
            let h
            if (dataArr && voiceAnalyser) {
                voiceAnalyser.getByteFrequencyData(dataArr)
                h = Math.max(10, (dataArr[i % dataArr.length] / 255) * 100)
            } else {
                h = 10 + Math.abs(Math.sin(Date.now() / 200 + i * 0.4)) * 90
            }
            b.style.height = h + '%'
        })
    }
    draw()
}

function stopWaveAnimation() {
    if (voiceWaveAnim) { cancelAnimationFrame(voiceWaveAnim); voiceWaveAnim = null }
    voiceAnalyser = null
    if (voiceAudioCtx) { voiceAudioCtx.close(); voiceAudioCtx = null }
}



async function sendVoiceMessage() {
    if (!voiceChunks.length || !currentChat) return

    const mimeType = mediaRecorder.mimeType || 'audio/webm'
    const blob = new Blob(voiceChunks, { type: mimeType })
    const duration = Math.round((Date.now() - voiceStartTime) / 1000)
    console.log(`[voice] blob size=${blob.size} type=${mimeType} duration=${duration}s chunks=${voiceChunks.length}`)
    if (blob.size < 100) { showToast('Запись пустая, попробуйте ещё раз'); return }

    // Скрываем строку записи с анимацией
    hideRecordArea()

    // Плейсхолдер в чате — появляется снизу
    const messagesDiv = document.getElementById('messages')
    const placeholder = document.createElement('div')
    placeholder.className = 'message voice-message me voice-sending'
    placeholder.style.cssText = 'opacity:0; transform:translateY(16px); transition:opacity 0.25s ease,transform 0.25s ease'
    placeholder.innerHTML = `
        <div class="voice-player">
            <button class="voice-play-btn" disabled><i class="fas fa-spinner fa-spin"></i></button>
            <div class="voice-wave-wrap">
                <div class="voice-wave-bars">
                    ${Array.from({length: 20}, (_, i) =>
                        `<div class="voice-wave-bar" style="height:${15+Math.random()*85}%"></div>`
                    ).join('')}
                </div>
                <div class="voice-progress-bar"><div class="voice-progress-fill"></div></div>
            </div>
            <span class="voice-time">${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}</span>
        </div>`
    messagesDiv.appendChild(placeholder)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
    // Запускаем анимацию появления
    requestAnimationFrame(() => {
        placeholder.style.opacity = '1'
        placeholder.style.transform = 'translateY(0)'
    })

    try {
        const res = await fetch('/api/voice/upload', {
            method: 'POST',
            headers: {
                'Content-Type': mimeType,
                'X-Sender': currentUser,
                'X-Duration': String(duration)
            },
            body: blob
        })
        const data = await res.json()

        if (!res.ok) {
            placeholder.remove()
            showToast(data.error || 'Ошибка отправки')
            return
        }

        // Убираем плейсхолдер — message_sent от сервера добавит настоящее
        placeholder.style.transition = 'opacity 0.2s'
        placeholder.style.opacity = '0'
        setTimeout(() => placeholder.remove(), 200)

        const voiceText = `[VOICE:${duration}]/api/voice/${data.voice_id}[/VOICE]`
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: 'send', to: currentChat, text: voiceText }))
        }
    } catch (err) {
        placeholder.remove()
        console.error('Send voice error:', err)
        showToast('Ошибка отправки')
    }
}

// Переключение кнопок send/mic/video в зависимости от текста
function updateInputButtons() {
    const hasText = (document.getElementById('text')?.value.trim().length ?? 0) > 0
    const sendBtn  = document.getElementById('sendBtn')
    const voiceBtn = document.getElementById('voiceBtn')
    const videoBtn = document.getElementById('videomsgBtn')
    if (sendBtn)  sendBtn.style.display  = hasText ? 'flex' : 'none'
    if (voiceBtn) voiceBtn.style.display = hasText ? 'none' : 'flex'
    if (videoBtn) videoBtn.style.display = hasText ? 'none' : 'flex'
}

document.addEventListener('DOMContentLoaded', () => {
    updateVoiceBtnBehavior()
    updateInputButtons()

    document.getElementById('text')?.addEventListener('input', updateInputButtons)
    document.getElementById('videomsgBtn')?.addEventListener('click', () => openVideoRecorder())
    document.getElementById('voiceBtn')?.addEventListener('mousedown', e => {
        if (e.button !== 0) return
        startVoiceRecord(null)
        const up = () => { stopVoiceRecord(null); document.removeEventListener('mouseup', up) }
        document.addEventListener('mouseup', up)
    })
})
if (document.readyState !== 'loading') {
    updateVoiceBtnBehavior()
    updateInputButtons()
    loadCameraSettings()
    document.getElementById('text')?.addEventListener('input', updateInputButtons)
}

function updateInputButtonsOLD_REMOVED() {}

// Также на десктопе — зажать кнопку мышью

// Плеер голосового сообщения
function createVoicePlayer(url, isMe, duration) {
    const wrap = document.createElement('div')
    wrap.className = 'voice-player'

    const playBtn = document.createElement('button')
    playBtn.className = 'voice-play-btn'
    playBtn.innerHTML = '<i class="fas fa-play"></i>'

    const waveWrap = document.createElement('div')
    waveWrap.className = 'voice-wave-wrap'

    // Псевдо-волна из 30 баров
    const bars = document.createElement('div')
    bars.className = 'voice-wave-bars'
    for (let i = 0; i < 30; i++) {
        const bar = document.createElement('div')
        bar.className = 'voice-wave-bar'
        bar.style.height = (20 + Math.random() * 60) + '%'
        bars.appendChild(bar)
    }

    const progress = document.createElement('div')
    progress.className = 'voice-progress-bar'
    const fill = document.createElement('div')
    fill.className = 'voice-progress-fill'
    progress.appendChild(fill)

    waveWrap.appendChild(bars)
    waveWrap.appendChild(progress)

    const timeEl = document.createElement('span')
    timeEl.className = 'voice-time'
    // Показываем длительность сразу из метаданных
    if (duration) {
        timeEl.textContent = `${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`
    } else {
        timeEl.textContent = '0:00'
    }

    wrap.appendChild(playBtn)
    wrap.appendChild(waveWrap)
    wrap.appendChild(timeEl)

    const audio = new Audio(url)
    let playing = false

    audio.addEventListener('loadedmetadata', () => {
        if (isFinite(audio.duration)) {
            const d = Math.floor(audio.duration)
            timeEl.textContent = `${Math.floor(d/60)}:${(d%60).toString().padStart(2,'0')}`
        }
        // Если Infinity — оставляем значение из duration параметра
    })

    audio.addEventListener('timeupdate', () => {
        const finite = isFinite(audio.duration) && audio.duration > 0
        const pct = finite ? (audio.currentTime / audio.duration) * 100 : 0
        fill.style.width = pct + '%'
        const barEls = bars.querySelectorAll('.voice-wave-bar')
        barEls.forEach((b, i) => {
            b.classList.toggle('played', i / barEls.length < pct / 100)
        })
        // Показываем текущее время если duration неизвестна, или оставшееся если известна
        const cur = Math.floor(audio.currentTime)
        if (finite) {
            const left = Math.max(0, Math.floor(audio.duration - audio.currentTime))
            timeEl.textContent = `${Math.floor(left/60)}:${(left%60).toString().padStart(2,'0')}`
        } else {
            timeEl.textContent = `${Math.floor(cur/60)}:${(cur%60).toString().padStart(2,'0')}`
        }
    })

    audio.addEventListener('ended', () => {
        playing = false
        playBtn.innerHTML = '<i class="fas fa-play"></i>'
        fill.style.width = '0%'
        bars.querySelectorAll('.voice-wave-bar').forEach(b => b.classList.remove('played'))
        if (duration) timeEl.textContent = `${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`
    })

    playBtn.onclick = () => {
        document.querySelectorAll('.voice-player').forEach(vp => {
            if (vp !== wrap) {
                const a = vp._audio
                if (a) { a.pause(); a.currentTime = 0 }
                const pb = vp.querySelector('.voice-play-btn')
                if (pb) pb.innerHTML = '<i class="fas fa-play"></i>'
            }
        })
        if (playing) {
            audio.pause()
            playBtn.innerHTML = '<i class="fas fa-play"></i>'
            playing = false
        } else {
            // Принудительно загружаем если ещё не загружено
            if (audio.readyState === 0) audio.load()
            const p = audio.play()
            if (p && p.catch) {
                p.catch(err => {
                    console.error('Voice play error:', err.name, err.message, 'url:', url)
                    playing = false
                    playBtn.innerHTML = '<i class="fas fa-play"></i>'
                    showToast('Ошибка: ' + err.name)
                })
            }
            playBtn.innerHTML = '<i class="fas fa-pause"></i>'
            playing = true
        }
    }

    // Сбрасываем состояние если audio сам остановился с ошибкой
    audio.addEventListener('error', (e) => {
        const code = audio.error?.code
        playing = false
        playBtn.innerHTML = '<i class="fas fa-play"></i>'
        if (code === 4) {
            // Повреждённый файл (старая запись) — показываем иконку
            playBtn.innerHTML = '<i class="fas fa-triangle-exclamation" style="color:#ff9500;font-size:12px;"></i>'
            playBtn.title = 'Запись повреждена'
            playBtn.disabled = true
        } else {
            console.error('Audio error:', code, audio.error?.message, 'url:', url)
            showToast('Не удалось воспроизвести аудио')
        }
    })

    wrap._audio = audio

    progress.addEventListener('click', e => {
        if (!audio.duration) return
        const rect = progress.getBoundingClientRect()
        audio.currentTime = audio.duration * ((e.clientX - rect.left) / rect.width)
    })

    return wrap
}

window.startVoiceRecord = startVoiceRecord
window.commitVoice = commitVoice
window.stopVoiceRecord  = stopVoiceRecord
window.cancelVoiceRecord = cancelVoiceRecord

// ============= РЕАКЦИИ =============

let currentMessageId = null
let reactionsPanelTimeout = null

// Показать панель реакций
function showReactionsPanel(event, messageId) {
    if (event && event.preventDefault) event.preventDefault()
    if (event && event.stopPropagation) event.stopPropagation()

    currentMessageId = messageId

    const panel = document.getElementById('reactionsPanel')
    if (!panel) return

    // Ищем элемент сообщения — от currentTarget или по messageId
    let messageElement = null
    if (event && event.currentTarget) {
        messageElement = event.currentTarget.closest('.message')
    }
    if (!messageElement) {
        messageElement = document.querySelector(`[data-message-id="${messageId}"]`)
    }
    if (!messageElement) return

    const rect = messageElement.getBoundingClientRect()
    const panelBottom = window.innerHeight - rect.top + 8
    const panelLeft   = Math.min(rect.left, window.innerWidth - 300)

    panel.style.bottom  = panelBottom + 'px'
    panel.style.left    = Math.max(8, panelLeft) + 'px'
    panel.style.display = 'block'

    clearTimeout(reactionsPanelTimeout)
    reactionsPanelTimeout = setTimeout(() => {
        panel.style.display = 'none'
    }, 5000)
}

// Добавить реакцию
async function addReaction(reaction) {
    if (!currentMessageId || !currentUser) return
    
    try {
        const res = await fetch('/reaction/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message_id: currentMessageId,
                user: currentUser,
                reaction: reaction
            })
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        // Обновляем отображение реакций на сообщении
        updateMessageReactions(currentMessageId, data.reactions)
        
    } catch (error) {
        console.error('Error adding reaction:', error)
        showToast('Ошибка при добавлении реакции')
    }
    
    // Скрываем панель
    document.getElementById('reactionsPanel').style.display = 'none'
}

// Обновить отображение реакций на сообщении
function updateMessageReactions(messageId, reactions) {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`)
    if (!messageElement) return
    
    // Удаляем старые реакции
    const oldReactions = messageElement.querySelector('.message-reactions')
    if (oldReactions) oldReactions.remove()
    
    if (reactions.length === 0) return
    
    // Создаем контейнер для реакций
    const reactionsDiv = document.createElement('div')
    reactionsDiv.className = 'message-reactions'
    
    reactions.forEach(r => {
        const badge = document.createElement('span')
        badge.className = 'reaction-badge'
        badge.onclick = (e) => {
            e.stopPropagation()
            // При клике на бейдж - добавляем/убираем реакцию
            addReaction(r.reaction)
        }
        badge.innerHTML = `${r.reaction} <span class="count">${r.count}</span>`
        reactionsDiv.appendChild(badge)
    })
    
    messageElement.appendChild(reactionsDiv)
}

// addMessage defined above

// Загрузить реакции для сообщения
async function loadMessageReactions(messageId) {
    try {
        const res = await fetch(`/reactions/${messageId}`)
        const data = await res.json()
        
        if (data.reactions && data.reactions.length > 0) {
            updateMessageReactions(messageId, data.reactions)
        }
    } catch (error) {
        console.error('Error loading reactions:', error)
    }
}

// ============= ФУНКЦИИ ДЛЯ ЧАТОВ =============

function formatLastMessage(text) {
    if (!text) return 'Нет сообщений'
    if (text.match(/^\[VIDEO/))  return '📹 Видео сообщение'
    if (text.match(/^\[VOICE/))   return '🎤 Голосовое сообщение'
    if (text.match(/^\[STICKER/)) return '🖼 Стикер'
    if (text.match(/^\[FWD:/))    return '↩ Пересланное сообщение'
    if (text.match(/^\[MUSIC/))  return '🎵 Музыкальный трек'
    return text
}

function createChatElement(chat) {
    const displayName = chat.displayName || chat.name || chat.username || chat.phone
    const lastMessage = formatLastMessage(chat.last)
    const unreadCount = chat.unread || 0
    
    let div = document.createElement('div')
    div.className = 'chatItem'
    div.id = `chat-${cleanPhone(chat.phone)}`
    
    if (chat.phone === currentChat) {
        div.classList.add('active')
    }
    
    let avatarHtml
    if (chat.avatar) {
        avatarHtml = `<img src="${chat.avatar}" class="chat-avatar-img" alt="avatar" onerror="this.onerror=null; this.parentElement.innerText='?'">`
    } else {
        avatarHtml = '?'
    }
    
    const isOnline = window.clients && window.clients[chat.phone] === true
    const unreadBadge = unreadCount > 0 ? 
        `<span class="unread-badge">${unreadCount > 99 ? '99+' : unreadCount}</span>` : ''
    
    div.innerHTML = `
        <div class="chat-avatar">${avatarHtml}</div>
        <div class="chat-info">
            <div class="chat-name">${escapeHtml(displayName)}</div>
            <div class="chat-last-message">${escapeHtml(lastMessage)}</div>
        </div>
        ${unreadBadge}
        <div class="chat-status ${isOnline ? '' : 'offline'}"></div>
    `
    // Staggered animation
    const idx = document.querySelectorAll('.chatItem').length
    div.style.animationDelay = `${Math.min(idx * 30, 200)}ms`
    
    let isLongPress = false
    
    div.addEventListener('mousedown', () => {
        isLongPress = false
    })
    
    div.addEventListener('mouseup', () => {
        if (!isLongPress) {
            openChat(chat.phone, displayName)
        }
    })
    
    div.addEventListener('touchstart', (e) => {
        isLongPress = false
        longPressTimer = setTimeout(() => {
            isLongPress = true
            if (window.navigator.vibrate) {
                window.navigator.vibrate(50)
            }
            showContextMenu(e, 'chat', { phone: chat.phone, element: div })
        }, 500)
    })
    
    div.addEventListener('touchend', (e) => {
        clearTimeout(longPressTimer)
        if (!isLongPress) {
            e.preventDefault()
            openChat(chat.phone, displayName)
        }
    })
    
    div.addEventListener('touchmove', () => {
        clearTimeout(longPressTimer)
        isLongPress = true
    })
    
    div.addEventListener('touchcancel', () => {
        clearTimeout(longPressTimer)
    })
    
    div.addEventListener('contextmenu', (e) => {
        e.preventDefault()
        showContextMenu(e, 'chat', { phone: chat.phone, element: div })
    })
    
    return div
}

// Обновляет чат в списке: last message, unread badge, позиция
// Кеш данных пользователей для мгновенного создания чатов
const userCache = {}

function updateChatInList(phone, lastText, incrementUnread = false) {
    const cleanPh = cleanPhone(phone)
    let chatEl = document.getElementById(`chat-${cleanPh}`)
    const list = document.getElementById('chatList')
    console.log('[updateChatInList]', phone, 'cleanPh=', cleanPh, 'chatEl=', !!chatEl, 'list=', !!list)
    if (!list) return

    if (!chatEl) {
        // Создаём элемент немедленно из кеша или с минимальными данными
        const cached = userCache[phone]
        const displayName = cached?.name || cached?.username || phone
        const avatarHtml = cached?.avatar
            ? `<img src="${cached.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover">`
            : `<span>${(displayName[0] || '?').toUpperCase()}</span>`
        chatEl = document.createElement('div')
        chatEl.className = 'chatItem'
        chatEl.id = `chat-${cleanPh}`
        chatEl.innerHTML = `
            <div class="chat-avatar">${avatarHtml}</div>
            <div class="chat-info">
                <div class="chat-name">${escapeHtml(displayName)}</div>
                <div class="chat-last-message">${formatLastMessage(lastText || '')}</div>
            </div>
            <div class="chat-status offline"></div>`
        chatEl.onclick = () => openChat(phone, displayName)
        list.prepend(chatEl)

        // Фоново загружаем данные и обновляем
        fetch(`/user/${encodeURIComponent(phone)}`)
            .then(r => r.json())
            .then(user => {
                userCache[phone] = user
                const nameEl = chatEl.querySelector('.chat-name')
                if (nameEl) nameEl.textContent = user.name || user.username || phone
                const av = chatEl.querySelector('.chat-avatar')
                if (av && user.avatar) av.innerHTML = `<img src="${user.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover">`
                const dot = chatEl.querySelector('.chat-status')
                if (dot) dot.className = `chat-status ${user.online ? '' : 'offline'}`
                chatEl.onclick = () => openChat(phone, user.name || user.username || phone)
            }).catch(() => {})

        if (incrementUnread) {
            const badge = document.createElement('div')
            badge.className = 'unread-badge'
            badge.textContent = '1'
            const statusDot = chatEl.querySelector('.chat-status')
            if (statusDot) chatEl.insertBefore(badge, statusDot)
            else chatEl.appendChild(badge)
        }
        return
    }

    // Обновляем последнее сообщение
    const lastEl = chatEl.querySelector('.chat-last-message')
    if (lastEl) lastEl.textContent = formatLastMessage(lastText)

    // Unread badge
    if (incrementUnread) {
        let badge = chatEl.querySelector('.unread-badge')
        if (!badge) {
            badge = document.createElement('div')
            badge.className = 'unread-badge'
            const statusDot = chatEl.querySelector('.chat-status')
            if (statusDot) chatEl.insertBefore(badge, statusDot)
            else chatEl.appendChild(badge)
        }
        const cur = parseInt(badge.textContent) || 0
        badge.textContent = cur + 1
        badge.style.display = 'flex'
    }

    // Перемещаем наверх
    list.prepend(chatEl)
}

async function loadChats() {
    if (!currentUser) {
        console.error('loadChats: currentUser is null')
        return
    }
    
    try {
        const url = `/users/${currentUser}`
        const res = await fetch(url)
        
        if (!res.ok) {
            throw new Error(`Failed to load chats: ${res.status}`)
        }
        
        let chats = await res.json()
        
        let list = document.getElementById('chatList')
        list.innerHTML = ''
        
        const chatsCount = document.getElementById('chatsCount')
        if (chatsCount) {
            chatsCount.textContent = chats.length
        }
        
        chats.sort((a, b) => {
            if (!a.last) return 1
            if (!b.last) return -1
            return 0
        })
        
        chats.forEach(chat => {
            userCache[chat.phone] = chat  // кешируем
            list.appendChild(createChatElement(chat))
        })
        
    } catch (error) {
        console.error('loadChats: error', error)
        showToast('Ошибка загрузки чатов')
    }
}

function openChat(phone, displayName) {
    if (currentChat === phone) return
    
    currentChat = phone
    // Если чата нет в списке — добавляем сразу
    if (!document.getElementById(`chat-${cleanPhone(phone)}`)) {
        createChatElement({ phone, displayName, name: displayName, last: '', unread: 0 })
    }
    // Применяем тему этого чата
    loadChatTheme(phone)
    
    fetch(`/user/${phone}`)
        .then(res => res.json())
        .then(user => {
            const name = user.name || user.username || phone
            document.getElementById('chatUserName').innerText = name
            // Сохраняем last_seen
            userCache[phone] = user  // кешируем для updateChatInList
            if (user.last_seen) lastSeenMap[phone] = user.last_seen
            document.getElementById('chatUserPhone').innerText = formatPhone(phone)
            
            const chatAvatar = document.getElementById('chatAvatarText')
            if (user.avatar) {
                chatAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText='?'">`
            } else {
                chatAvatar.innerText = '?'
            }
            
            if (user.last_seen) lastSeenMap[phone] = user.last_seen
            const isOnline = window.clients && window.clients[phone] === true
            updateChatStatusText(phone, isOnline)
        })
        .catch(() => {
            document.getElementById('chatUserName').innerText = displayName || phone
            document.getElementById('chatUserPhone').innerText = formatPhone(phone)
            document.getElementById('chatAvatarText').innerText = '?'
        })
    
    document.getElementById('emptyChat').style.display = 'none'
    document.getElementById('chatBlock').style.display = 'flex'
    
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('open')
    }
    
    loadMessages()
    
    // Сбрасываем unread badge
    const chatElCurrent = document.getElementById(`chat-${cleanPhone(phone)}`)
    if (chatElCurrent) {
        const badge = chatElCurrent.querySelector('.unread-badge')
        if (badge) badge.remove()
        chatElCurrent.classList.add('active')
    }
    document.querySelectorAll('.chatItem').forEach(el => {
        if (el.id !== `chat-${cleanPhone(phone)}`) el.classList.remove('active')
    })
    
    const activeChat = document.getElementById(`chat-${cleanPhone(phone)}`)
    if (activeChat) {
        activeChat.classList.add('active')
    }
}

function loadMessages() {
    if (!currentChat) return
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        setTimeout(loadMessages, 300)
        return
    }
    ws.send(JSON.stringify({ action: 'history', user: currentChat }))
}

function send() {
    if (!currentChat) { showToast('Выберите чат'); return }
    if (!ws || ws.readyState !== WebSocket.OPEN) { showToast('Нет соединения с сервером'); return }

    const text = document.getElementById('text').value.trim()
    if (!text) return

    ws.send(JSON.stringify({ action: 'send', to: currentChat, text }))
    document.getElementById('text').value = ''
    updateInputButtons()
    // Сразу обновляем список чатов (создаёт если новый)
    updateChatInList(currentChat, text, false)
}

// ============= КОНТЕКСТНОЕ МЕНЮ =============

function showContextMenu(event, type, data) {
    if (event.preventDefault) event.preventDefault()
    if (event.stopPropagation) event.stopPropagation()
    
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    
    let menuId
    
    if (type === 'message') {
        menuId = 'messageContextMenu'
        selectedMessageId = data.messageId
        selectedMessageElement = data.element
        selectedMessageText = data.text || ''
        selectedMessageSender = data.sender || currentUser
    } else {
        menuId = 'chatContextMenu'
        selectedChatPhone = data.phone
        selectedChatElement = data.element
    }
    
    const menu = document.getElementById(menuId)
    
    let x, y
    if (event.touches && event.touches[0]) {
        x = event.touches[0].pageX
        y = event.touches[0].pageY
    } else if (event.pageX !== undefined) {
        x = event.pageX
        y = event.pageY
    } else {
        // Fallback — позиционируем по центру элемента
        const el = data.element
        if (el) {
            const r = el.getBoundingClientRect()
            x = r.left + r.width / 2
            y = r.top + window.scrollY
        } else {
            x = window.innerWidth / 2
            y = window.innerHeight / 2
        }
    }
    
    menu.style.display = 'block'
    menu.style.left = x + 'px'
    menu.style.top = y + 'px'
    
    setTimeout(() => {
        const rect = menu.getBoundingClientRect()
        if (rect.right > window.innerWidth) {
            menu.style.left = (window.innerWidth - rect.width - 10) + 'px'
        }
        if (rect.bottom > window.innerHeight) {
            menu.style.top = (window.innerHeight - rect.height - 10) + 'px'
        }
    }, 0)
}

function hideContextMenus() {
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    selectedMessageId = null
    selectedMessageElement = null
    selectedMessageText = null
    selectedMessageSender = null
    selectedChatElement = null
}

async function deleteMessage() {
    if (!selectedMessageId || !selectedMessageElement) return
    const el = selectedMessageElement
    const id = selectedMessageId
    hideContextMenus()
    el.style.transition = 'transform 0.2s,opacity 0.2s'
    el.style.transform = 'scale(0.85)'; el.style.opacity = '0'
    setTimeout(() => el.remove(), 200)
    try {
        const res = await fetch(`/message/${id}?user=${encodeURIComponent(currentUser)}`, { method: 'DELETE' })
        if (!res.ok) {
            el.style.transform = ''; el.style.opacity = ''
            if (!el.parentElement) document.getElementById('messages')?.appendChild(el)
            const d = await res.json(); showToast(d.error || 'Ошибка при удалении')
        }
    } catch { showToast('Нет соединения') }
}

async function deleteChat() {
    if (!selectedChatPhone) return
    const phone = selectedChatPhone
    const el = document.getElementById(`chat-${cleanPhone(phone)}`)
    const wasOpen = currentChat === phone
    hideContextMenus()
    if (el) {
        el.style.transition = 'opacity 0.2s,transform 0.2s'
        el.style.opacity = '0'; el.style.transform = 'translateX(-20px)'
        setTimeout(() => el.remove(), 200)
    }
    if (wasOpen) {
        currentChat = null
        resetChatThemeStyles()
    document.getElementById('messages').innerHTML = ''
        document.getElementById('emptyChat').style.display = 'flex'
        document.getElementById('chatBlock').style.display = 'none'
        if (window.innerWidth <= 768) document.getElementById('sidebar')?.classList.add('open')
    }
    fetch(`/chat/${encodeURIComponent(currentUser)}/${encodeURIComponent(phone)}`, { method: 'DELETE' })
        .catch(() => showToast('Ошибка при удалении'))
}

function muteChat() {
    if (!selectedChatPhone) return
    showToast('Чат заглушен')
    hideContextMenus()
}

function clearChat() {
    if (!selectedChatPhone) return
    const phone = selectedChatPhone
    hideContextMenus()
    fetch('/chat/' + encodeURIComponent(currentUser) + '/' + encodeURIComponent(phone), { method: 'DELETE' })
        .then(() => { if (currentChat === phone) document.getElementById('messages').innerHTML = ''; showToast('История очищена') })
        .catch(() => showToast('Ошибка при очистке'))
}

// ============= ПЕРЕСЫЛКА =============

function forwardMessage() {
    if (!selectedMessageText) return
    // Если это стикер — текст содержит [STICKER]url[/STICKER]
    const text = selectedMessageText, sender = selectedMessageSender
    hideContextMenus()
    const modal = document.getElementById('forwardModal')
    const list  = document.getElementById('forwardChatList')
    if (!modal || !list) return
    const prev = document.getElementById('forwardPreviewText')
    if (prev) prev.textContent = text.length > 80 ? text.slice(0,80)+'…' : text
    list.innerHTML = ''
    document.querySelectorAll('.chatItem').forEach(item => {
        const phone = item.id.replace('chat-','')
        if (!phone) return
        const name = item.querySelector('.chat-name')?.textContent || phone
        const div = document.createElement('div')
        div.className = 'forward-chat-item'
        const av = document.createElement('div')
        av.className = 'forward-chat-avatar'
        const img = item.querySelector('.chat-avatar img')
        if (img) { const i=document.createElement('img'); i.src=img.src; av.appendChild(i) }
        else av.textContent = name[0]?.toUpperCase() || '?'
        const nd = document.createElement('div')
        nd.className = 'forward-chat-name'; nd.textContent = name
        div.appendChild(av); div.appendChild(nd)
        div.onclick = () => sendForwarded(phone, text, sender)
        list.appendChild(div)
    })
    modal.classList.add('show')
}

function closeForwardModal() {
    document.getElementById('forwardModal')?.classList.remove('show')
}

function sendForwarded(toPhone, text, originalSender) {
    if (!ws || ws.readyState !== WebSocket.OPEN) { showToast('Нет соединения'); return }
    let fwdText
    if (text.startsWith('[STICKER]') || text.startsWith('[VIDEO')) {
        fwdText = text
    } else {
        // Формат: [FWD:имя|телефон]текст[/FWD]
        const senderPhone = originalSender || currentUser
        const senderName = originalSender === currentUser
            ? (currentUserProfile?.name || currentUserProfile?.username || currentUser)
            : originalSender
        fwdText = `[FWD:${senderName}|${senderPhone}]${text}[/FWD]`
    }
    ws.send(JSON.stringify({ action: 'send', to: toPhone, text: fwdText }))
    // Не добавляем вручную — message_sent от сервера добавит само
    if (toPhone !== currentChat) showToast('Сообщение переслано')
    closeForwardModal()
}

// ============= WEBSOCKET =============

function connect() {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)

    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/ws/${currentUser}`
        
        ws = new WebSocket(wsUrl)

        ws.onopen = () => {
            isConnected = true
            reconnectAttempts = 0
            
            setTimeout(() => {
                broadcastOnlineStatus(true)
            }, 500)
            
            pingInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'ping' }))
                }
            }, 30000)
        }

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data)

            if (data.action === 'pong') return

            if (data.action === 'status') {
                console.log('[WS status]', data)
                if (data.from) {
                    if (!window.clients) window.clients = {}
                    window.clients[data.from] = data.online
                    const contactId = `chat-${cleanPhone(data.from)}`
                    const chatEl = document.getElementById(contactId)
                    if (chatEl) {
                        const dot = chatEl.querySelector('.chat-status')
                        if (dot) dot.className = `chat-status ${data.online ? '' : 'offline'}`
                    }
                    if (currentChat === data.from) {
                        if (!data.online && !lastSeenMap[data.from]) {
                            // Запрашиваем last_seen если не знаем
                            fetch('/user/' + data.from)
                                .then(r => r.json())
                                .then(u => { if (u.last_seen) lastSeenMap[data.from] = u.last_seen })
                                .catch(() => {})
                        }
                        updateChatStatusText(data.from, data.online)
                    }
                }
            }

            if (data.action === 'last_seen') {
                console.log('[WS last_seen]', data)
                if (data.from && data.last_seen) {
                    lastSeenMap[data.from] = data.last_seen
                    if (currentChat === data.from) updateChatStatusText(data.from, false)
                }
            }

            if (data.action === 'messages_read') {
                console.log('[WS messages_read]', data.ids)
                if (data.ids) data.ids.forEach(id => {
                    const el = document.querySelector(`[data-message-id="${id}"]`)
                    if (el) {
                        const t = el.querySelector('.msg-ticks')
                        if (t) {
                            t.classList.add('read')
                            const tick2 = t.querySelector('.tick-second')
                            if (tick2) tick2.style.display = ''
                        }
                    }
                })
                // Скрываем unread badge в списке чатов для текущего собеседника
                // (это наши исходящие были прочитаны — не трогаем badge)
            }

            if (data.action === 'message_deleted') {
                const el = document.querySelector(`[data-message-id="${data.id}"]`)
                if (el) {
                    el.style.transition = 'transform 0.2s,opacity 0.2s'
                    el.style.transform = 'scale(0.85)'; el.style.opacity = '0'
                    setTimeout(() => el.remove(), 200)
                }
            }

            if (data.action === 'message') {
                // Подтверждаем доставку
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'delivered', id: data.id, to: data.from }))
                }

                // Добавляем в DOM только если это открытый чат
                if (currentChat === data.from) {
                    addMessage(data.from, data.text, data.id, false)
                    // Отмечаем прочитанным и скрываем badge
                    ws.send(JSON.stringify({ action: 'read', from: data.from, id: data.id }))
                    const incomingChatEl = document.getElementById(`chat-${cleanPhone(data.from)}`)
                    if (incomingChatEl) {
                        const badge = incomingChatEl.querySelector('.unread-badge')
                        if (badge) badge.remove()
                    }
                }

                // Обновляем список чатов
                const isOpen = currentChat === data.from
                updateChatInList(data.from, data.text, !isOpen)

                // Уведомление если чат не открыт
                if (!isOpen) {
                    showToast(`Новое сообщение`)
                    if (window.navigator.vibrate) window.navigator.vibrate(200)
                }
            }

            if (data.action === 'message_sent') {
                addMessage(currentUser, data.text, data.id, null)
                if (data.delivered) {
                    const el = document.querySelector(`[data-message-id="${data.id}"] .msg-ticks .tick-second`)
                    if (el) el.style.display = ''
                }
                // Обновляем last message в списке чатов
                if (currentChat) updateChatInList(currentChat, data.text, false)
            }

            if (data.action === 'history') {
                document.getElementById('messages').innerHTML = ''
                data.messages.forEach(m => addMessage(m[1], m[2], m[0], m[3] === 1))
            }

            if (data.action === 'typing') {
                if (currentChat === data.from) {
                    document.getElementById('chatUserStatus').textContent = 'печатает...'
                    clearTimeout(window.typingStatusTimeout)
                    window.typingStatusTimeout = setTimeout(() => {
                        if (currentChat === data.from) {
                            updateChatStatusText(data.from, window.clients && window.clients[data.from])
                        }
                    }, 3000)
                }
            }
            if (data.action === 'music_status') {
                // Обновляем статус "слушает" в профиле если открыт
                const statusEl = document.getElementById('modalStatus')
                if (statusEl && document.getElementById('profileModal')._profilePhone === data.phone && data.is_playing) {
                    const oldStatus = statusEl.innerHTML
                    statusEl.innerHTML = `<span style="color:var(--accent)">🎵 Слушает: ${escapeHtml(data.track_name)} — ${escapeHtml(data.artist_name)}</span>`
                    setTimeout(() => { if (statusEl.innerHTML.includes('Слушает')) statusEl.innerHTML = oldStatus }, 30000)
                }
            }
        }

        ws.onclose = () => {
            broadcastOnlineStatus(false)
            
            if (window.clients) {
                Object.keys(window.clients).forEach(key => {
                    window.clients[key] = false
                })
            }
            
            isConnected = false
            if (pingInterval) clearInterval(pingInterval)
            handleReconnect()
        }

        ws.onerror = (error) => {
            console.error('WebSocket error:', error)
        }

    } catch (error) {
        console.error('Connection error:', error)
        handleReconnect()
    }
}

function handleReconnect() {
    if (reconnectAttempts < maxReconnectAttempts && currentUser) {
        reconnectAttempts++
        const delay = 1000 * Math.pow(2, reconnectAttempts)
        reconnectTimeout = setTimeout(connect, delay)
    }
}

// ============= ПОИСК =============

async function searchUsers(query) {
    if (query.length < 2) {
        hideSearchResults()
        return
    }
    
    try {
        const res = await fetch(`/search-users/${encodeURIComponent(query)}`)
        const data = await res.json()
        displaySearchResults(data.users)
        
    } catch (error) {
        console.error('Search error:', error)
    }
}

function displaySearchResults(users) {
    const resultsDiv = document.getElementById('searchResults')
    resultsDiv.innerHTML = ''
    
    if (users.length === 0) {
        resultsDiv.innerHTML = '<div class="search-no-results">Ничего не найдено</div>'
        resultsDiv.style.display = 'block'
        return
    }
    
    users.forEach(user => {
        const div = document.createElement('div')
        div.className = 'search-result-item'
        
        let avatarHtml
        if (user.avatar) {
            avatarHtml = `<img src="${user.avatar}" alt="avatar">`
        } else {
            avatarHtml = '?'
        }
        
        div.innerHTML = `
            <div class="search-result-avatar">${avatarHtml}</div>
            <div class="search-result-info">
                <div class="search-result-name">${escapeHtml(user.displayName)}</div>
                <div class="search-result-username">${escapeHtml(user.username || '')}</div>
            </div>
        `
        
        div.onclick = () => {
            document.getElementById('searchUser').value = user.username || user.name || ''
            hideSearchResults()
            openChat(user.phone, user.displayName)
        }
        
        resultsDiv.appendChild(div)
    })
    
    resultsDiv.style.display = 'block'
}

function hideSearchResults() {
    document.getElementById('searchResults').style.display = 'none'
}

async function searchExactUser(username) {
    if (!username) {
        showToast("Введите username")
        return
    }

    try {
        const res = await fetch("/search", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        })

        const data = await res.json()

        if (!data.found) {
            showToast("Пользователь не найден")
            return
        }

        showUserProfile(data.phone, false)
        document.getElementById("searchUser").value = ""
        hideSearchResults()

    } catch (error) {
        console.error("Search error:", error)
        showToast("Ошибка при поиске")
    }
}

// ============= НАСТРОЙКИ =============

function openSettings() {
    const modal = document.getElementById('settingsModal')
    loadPrivacySettings()
    loadVoiceModeSetting()
    loadCameraSettings()
    modal.classList.add('show')
}

function closeSettings() {
    document.getElementById('settingsModal').classList.remove('show')
}

async function loadPrivacySettings() {
    if (!currentUser) return
    
    try {
        const res = await fetch(`/privacy-settings/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load settings')
        
        const settings = await res.json()
        
        document.getElementById('phonePrivacy').value = settings.phone_privacy || 'everyone'
        document.getElementById('onlinePrivacy').value = settings.online_privacy || 'everyone'
        document.getElementById('avatarPrivacy').value = settings.avatar_privacy || 'everyone'
        
    } catch (error) {
        console.error('Error loading privacy settings:', error)
        showToast('Ошибка загрузки настроек')
    }
}

async function savePhonePrivacy() {
    await saveAllPrivacySettings()
}

async function saveOnlinePrivacy() {
    await saveAllPrivacySettings()
}

async function saveAvatarPrivacy() {
    await saveAllPrivacySettings()
}

async function saveAllPrivacySettings() {
    if (!currentUser) return
    
    const settings = {
        phone_privacy: document.getElementById('phonePrivacy').value,
        online_privacy: document.getElementById('onlinePrivacy').value,
        avatar_privacy: document.getElementById('avatarPrivacy').value
    }
    
    try {
        const res = await fetch(`/privacy-settings/${currentUser}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        })
        
        if (!res.ok) throw new Error('Failed to save settings')
        
        showToast('Настройки сохранены')
        
    } catch (error) {
        console.error('Error saving privacy settings:', error)
        showToast('Ошибка сохранения настроек')
    }
}

function openBlockedUsers() {
    showToast('Функция в разработке')
    closeSettings()
}

function openSessions() {
    showToast('Функция в разработке')
    closeSettings()
}

async function clearAllChats() {
    if (!confirm('Вы уверены? Все чаты и сообщения будут удалены. Это действие нельзя отменить.')) {
        return
    }
    
    try {
        const res = await fetch('/clear-all-chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user: currentUser })
        })
        
        if (res.ok) {
            document.getElementById('chatList').innerHTML = ''
            document.getElementById('chatsCount').textContent = '0'
            
            if (currentChat) {
                document.getElementById('messages').innerHTML = ''
                currentChat = null
                document.getElementById('emptyChat').style.display = 'flex'
                document.getElementById('chatBlock').style.display = 'none'
            }
            
            chatsCache = {}
            unreadCounts = {}
            
            showToast('Все чаты очищены')
            closeSettings()
        }
        
    } catch (error) {
        console.error('Error clearing all chats:', error)
        showToast('Ошибка при очистке')
    }
}

async function exportData() {
    showToast('Подготовка данных...')
    
    try {
        const res = await fetch(`/export-data/${currentUser}`)
        if (!res.ok) throw new Error('Export failed')
        
        const data = await res.json()
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `nonblock-data-${new Date().toISOString().slice(0,10)}.json`
        a.click()
        URL.revokeObjectURL(url)
        
        showToast('Данные экспортированы')
        closeSettings()
        
    } catch (error) {
        console.error('Error exporting data:', error)
        showToast('Ошибка при экспорте')
    }
}

// ============= ИНДИКАТОР ПЕЧАТАНИЯ =============

document.getElementById('text')?.addEventListener('input', () => {
    if (!currentChat || !ws || ws.readyState !== WebSocket.OPEN) return
    
    clearTimeout(typingTimeout)
    
    ws.send(JSON.stringify({
        action: 'typing',
        to: currentChat
    }))
    
    typingTimeout = setTimeout(() => {}, 2000)
})

// ============= ОБРАБОТЧИКИ СОБЫТИЙ =============

// Скрываем меню только если клик/тач НЕ внутри самого меню
document.addEventListener('click', (e) => {
    if (!e.target.closest('.context-menu')) hideContextMenus()
})
document.addEventListener('touchend', (e) => {
    if (!e.target.closest('.context-menu') && !e.target.closest('.message')) {
        setTimeout(() => hideContextMenus(), 150)
    }
})

document.addEventListener('contextmenu', (e) => {
    // Блокируем системное меню на сообщениях и чатах
    if (e.target.closest('.message') || e.target.closest('.chatItem')) {
        e.preventDefault()
    }
})

document.getElementById('text')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        send()
    }
})

document.getElementById('searchUser')?.addEventListener('input', (e) => {
    const query = e.target.value.trim()
    
    if (searchTimeout) clearTimeout(searchTimeout)
    
    if (query.length < 2) {
        hideSearchResults()
        return
    }
    
    searchTimeout = setTimeout(() => {
        searchUsers(query)
    }, 300)
})

document.getElementById('searchUser')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault()
        searchExactUser(e.target.value.trim())
    }
})

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal()
        closeAvatarEditor()
        closeChangePassword()
        closePasswordSetup()
        closeStickerModal()
    }
})

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPhone').focus()
    // Пре-рендер категорий эмодзи при загрузке страницы
    // (не сетку, только catBar — чтобы RAF внутри модала мог работать быстро)
})

window.addEventListener('online', () => {
    showToast('Соединение восстановлено')
    if (!isConnected && currentUser) {
        connect()
    }
})

window.addEventListener('offline', () => {
    showToast('Потеряно соединение с интернетом')
})

window.addEventListener('beforeunload', () => {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)
    if (ws) ws.close(1000, 'Page closed')
})

setInterval(updateOnlineStatus, 5000)
setInterval(() => {
    if (currentChat && window.clients && !window.clients[currentChat]) updateChatStatusText(currentChat, false)
}, 60000)

// ============= УДАЛЕНИЕ СТИКЕРА =============
async function cleanBrokenStickers() {
    try {
        const res = await fetch(`/api/stickers-broken/${encodeURIComponent(currentUser)}`, { method: 'DELETE' })
        const data = await res.json()
        showToast(`Удалено ${data.deleted} устаревших стикеров`)
        await loadStickers()
    } catch(e) {
        showToast('Ошибка очистки')
    }
}
// ============= УДАЛЕНИЕ СТИКЕРА =============
async function deleteSticker(stickerId, element) {
    try {
        element.style.transition = 'transform 0.2s, opacity 0.2s'
        element.style.transform = 'scale(0.5)'
        element.style.opacity = '0'
        setTimeout(() => element.remove(), 200)
        await fetch(`/api/stickers/${encodeURIComponent(currentUser)}/${stickerId}`, { method: 'DELETE' })
        userStickers = userStickers.filter(s => s.id !== stickerId)
    } catch (e) {
        console.error('deleteSticker error', e)
    }
}

// Алиасы для голосовых (HTML использует короткие имена)
const startVoice  = startVoiceRecord
const stopVoice   = stopVoiceRecord
const cancelVoice = cancelVoiceRecord
window.startVoice  = startVoiceRecord
window.stopVoice   = stopVoiceRecord
window.cancelVoice = cancelVoiceRecord


// ============= ВИДЕО СООБЩЕНИЯ =============

let videoStream = null
let videoRecorder = null
let videoChunks = []
let videoStartTime = null
let videoTimer = null
let videoBlob = null

async function openVideoRecorder() {
    if (!currentChat) { showToast('Сначала откройте чат'); return }
    const modal = document.getElementById('videoRecorderModal')
    if (!modal) return
    modal.style.display = 'flex'
    document.body.style.overflow = 'hidden'
    resetVideoRing()
    document.getElementById('videoSendActions').style.display = 'none'
    document.getElementById('videoRecorderActions').style.display = 'flex'
    document.getElementById('videoTimer').style.display = 'none'
    document.getElementById('videoPreview').style.display = 'block'
    document.getElementById('videoPlayback').style.display = 'none'
    videoBlob = null

    try {
        videoStream = await navigator.mediaDevices.getUserMedia(getCameraConstraints())
        const preview = document.getElementById('videoPreview')
        preview.srcObject = videoStream
    } catch (e) {
        let msg = 'Нет доступа к камере'
        if (e.name === 'NotAllowedError')  msg = 'Камера заблокирована. Разрешите доступ в настройках браузера'
        if (e.name === 'NotFoundError')    msg = 'Камера не найдена'
        if (e.name === 'NotReadableError') msg = 'Камера занята другим приложением'
        if (e.name === 'OverconstrainedError') msg = 'Камера не поддерживает нужный формат'
        showToast(msg)
        closeVideoRecorder()
    }
}

function closeVideoRecorder() {
    stopVideoStream()
    const modal = document.getElementById('videoRecorderModal')
    if (modal) modal.style.display = 'none'
    document.body.style.overflow = ''
    videoBlob = null
    videoChunks = []
}

function stopVideoStream() {
    clearInterval(videoTimer)
    if (videoRecorder && videoRecorder.state !== 'inactive') {
        videoRecorder.stop()
    }
    if (videoStream) {
        videoStream.getTracks().forEach(t => t.stop())
        videoStream = null
    }
    // Обязательно сбрасываем srcObject — иначе камера не выключается
    const preview = document.getElementById('videoPreview')
    if (preview) { preview.srcObject = null }
}

function toggleVideoRecord() {
    const btn = document.getElementById('vrRecordBtn')
    if (!videoRecorder || videoRecorder.state === 'inactive') {
        // Начинаем запись
        videoChunks = []
        const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp9,opus')
            ? 'video/webm;codecs=vp9,opus'
            : MediaRecorder.isTypeSupported('video/webm') ? 'video/webm' : 'video/mp4'

        videoRecorder = new MediaRecorder(videoStream, mimeType ? { mimeType } : {})
        videoRecorder.ondataavailable = e => { if (e.data.size > 0) videoChunks.push(e.data) }
        videoRecorder.onstop = () => onVideoRecordStop()
        videoRecorder.start(100)

        videoStartTime = Date.now()
        btn.innerHTML = '<i class="fas fa-stop"></i>'
        btn.classList.add('recording')
        document.getElementById('videoTimer').style.display = 'block'

        // Прогресс кольцо
        videoTimer = setInterval(() => {
            const sec = (Date.now() - videoStartTime) / 1000
            const m = Math.floor(sec / 60), s = Math.floor(sec % 60)
            document.getElementById('videoTimer').textContent = `${m}:${s.toString().padStart(2,'0')}`
            updateVideoRing(sec / videoMaxDuration)
            if (sec >= videoMaxDuration) {
                toggleVideoRecord()  // авто-стоп
            }
        }, 100)
    } else {
        // Останавливаем
        clearInterval(videoTimer)
        videoRecorder.requestData()
        setTimeout(() => videoRecorder.stop(), 50)
        btn.innerHTML = '<i class="fas fa-circle"></i>'
        btn.classList.remove('recording')
    }
}

function onVideoRecordStop() {
    const mimeType = videoRecorder?.mimeType || 'video/webm'
    videoBlob = new Blob(videoChunks, { type: mimeType })

    const playback = document.getElementById('videoPlayback')
    const preview  = document.getElementById('videoPreview')
    const ring     = document.getElementById('videoProgressRing')
    const previewCirc = document.querySelector('.video-recorder-circle')

    playback.src = URL.createObjectURL(videoBlob)
    preview.style.display = 'none'
    playback.style.display = 'block'
    playback.load()

    // Убираем старую play-кнопку если была
    const oldBtn = previewCirc?.querySelector('.preview-play-btn')
    if (oldBtn) oldBtn.remove()

    // Добавляем кастомную кнопку Play поверх предпросмотра
    const playBtn = document.createElement('button')
    playBtn.className = 'preview-play-btn'
    playBtn.style.cssText = 'position:absolute;inset:0;margin:auto;width:56px;height:56px;border-radius:50%;background:rgba(0,0,0,0.55);color:white;border:none;font-size:22px;cursor:pointer;z-index:10;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)'
    playBtn.innerHTML = '<i class="fas fa-play"></i>'
    previewCirc?.appendChild(playBtn)

    let previewPlaying = false
    playBtn.onclick = (e) => {
        e.stopPropagation()
        if (previewPlaying) {
            playback.pause()
            playBtn.innerHTML = '<i class="fas fa-play"></i>'
        } else {
            playback.play().catch(() => {})
            playBtn.innerHTML = '<i class="fas fa-pause"></i>'
        }
        previewPlaying = !previewPlaying
    }
    playback.onended = () => {
        previewPlaying = false
        playBtn.innerHTML = '<i class="fas fa-play"></i>'
        playback.currentTime = 0
        if (ring) ring.style.strokeDashoffset = String(2 * Math.PI * 105)
    }

    // Обновляем кольцо прогресса
    const circLen = 2 * Math.PI * 105
    playback.ontimeupdate = () => {
        if (!playback.duration || !isFinite(playback.duration)) return
        const pct = playback.currentTime / playback.duration
        if (ring) ring.style.strokeDashoffset = String(circLen * (1 - pct))
    }

    // Перемотка drag по кружку предпросмотра
    if (previewCirc && !previewCirc._seekBound) {
        previewCirc._seekBound = true
        let seeking = false

        function previewAngle(e) {
            const rc = previewCirc.getBoundingClientRect()
            const cx = rc.left + rc.width / 2, cy = rc.top + rc.height / 2
            const px = e.touches ? e.touches[0].clientX : e.clientX
            const py = e.touches ? e.touches[0].clientY : e.clientY
            let a = Math.atan2(px - cx, -(py - cy))
            if (a < 0) a += 2 * Math.PI
            return a / (2 * Math.PI)
        }

        previewCirc.addEventListener('mousedown', (e) => {
            if (e.target === playBtn || e.target.closest('.preview-play-btn')) return
            if (!playback.duration || playback.style.display === 'none') return
            seeking = true; playback.pause()
            playback.currentTime = previewAngle(e) * playback.duration
            e.preventDefault()
        })
        previewCirc.addEventListener('touchstart', (e) => {
            if (e.target === playBtn || e.target.closest('.preview-play-btn')) return
            if (!playback.duration || playback.style.display === 'none') return
            seeking = true; playback.pause()
            playback.currentTime = previewAngle(e) * playback.duration
            e.preventDefault()
        }, { passive: false })
        let pendingPreviewSeek = null
        document.addEventListener('mousemove', (e) => {
            if (!seeking || !playback.duration) return
            const pct = previewAngle(e)
            const circLen2 = 2 * Math.PI * 105
            if (ring) ring.style.strokeDashoffset = String(circLen2 * (1 - pct))
            if (pendingPreviewSeek !== null) return
            pendingPreviewSeek = pct
            setTimeout(() => {
                if (playback.duration) {
                    const t = pendingPreviewSeek * playback.duration
                    if (playback.fastSeek) playback.fastSeek(t)
                    else playback.currentTime = t
                }
                pendingPreviewSeek = null
            }, 80)
        })
        document.addEventListener('mouseup', () => { seeking = false })
        document.addEventListener('touchmove', (e) => {
            if (!seeking || !playback.duration) return
            const pct = previewAngle(e)
            const circLen3 = 2 * Math.PI * 105
            if (ring) ring.style.strokeDashoffset = String(circLen3 * (1 - pct))
            if (pendingPreviewSeek !== null) return
            pendingPreviewSeek = pct
            setTimeout(() => {
                if (playback.duration) {
                    const t = pendingPreviewSeek * playback.duration
                    if (playback.fastSeek) playback.fastSeek(t)
                    else playback.currentTime = t
                }
                pendingPreviewSeek = null
            }, 80)
        })
        document.addEventListener('touchend', () => { seeking = false })
    }

    document.getElementById('videoRecorderActions').style.display = 'none'
    document.getElementById('videoSendActions').style.display = 'flex'
    document.getElementById('videoTimer').style.display = 'none'
}

function retakeVideo() {
    videoBlob = null
    videoChunks = []
    document.getElementById('videoPlayback').style.display = 'none'
    document.getElementById('videoPreview').style.display = 'block'
    document.getElementById('videoSendActions').style.display = 'none'
    document.getElementById('videoRecorderActions').style.display = 'flex'
    document.getElementById('vrRecordBtn').innerHTML = '<i class="fas fa-circle"></i>'
    document.getElementById('vrRecordBtn').classList.remove('recording')
    resetVideoRing()

    // Перезапускаем стрим если нужно
    if (!videoStream || videoStream.getTracks().some(t => t.readyState === 'ended')) {
        openVideoRecorder()
    }
}

async function sendVideoMessage() {
    if (!videoBlob || !currentChat) return
    // Сохраняем до closeVideoRecorder который обнуляет эти переменные
    const blobToSend = videoBlob
    const chatTo = currentChat
    const duration = Math.round((Date.now() - videoStartTime) / 1000)
    closeVideoRecorder()

    // Плейсхолдер в чате
    const messagesDiv = document.getElementById('messages')
    const placeholder = document.createElement('div')
    placeholder.className = 'message me video-msg-placeholder'
    placeholder.style.cssText = 'opacity:0;transform:translateY(16px);transition:opacity 0.25s,transform 0.25s'
    placeholder.innerHTML = `<div class="video-msg-outer" style="position:relative;width:216px;height:216px">
        <div style="position:absolute;inset:10px;border-radius:50%;background:rgba(0,0,0,0.35);display:flex;align-items:center;justify-content:center">
            <i class="fas fa-spinner fa-spin" style="font-size:28px;color:rgba(255,255,255,0.8)"></i>
        </div>
    </div>`
    messagesDiv.appendChild(placeholder)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
    requestAnimationFrame(() => { placeholder.style.opacity='1'; placeholder.style.transform='translateY(0)' })

    try {
        const res = await fetch('/api/video/upload', {
            method: 'POST',
            headers: {
                'Content-Type': blobToSend.type || 'video/webm',
                'X-Sender': currentUser,
                'X-Duration': String(duration)
            },
            body: blobToSend
        })
        const data = await res.json()
        if (!res.ok) {
            placeholder.style.opacity = '0'
            setTimeout(() => placeholder.remove(), 200)
            showToast('Ошибка: ' + (data.error || res.status))
            return
        }
        placeholder.style.opacity = '0'
        setTimeout(() => placeholder.remove(), 200)

        const videoText = `[VIDEO:${duration}]/api/video/${data.video_id}[/VIDEO]`
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: 'send', to: chatTo, text: videoText }))
        }
    } catch (e) {
        placeholder.remove()
        showToast('Ошибка отправки видео')
    }
}

// Прогресс-кольцо SVG
function updateVideoRing(pct) {
    const ring = document.getElementById('videoProgressRing')
    if (!ring) return
    const r = 105
    const circ = 2 * Math.PI * r
    ring.style.strokeDashoffset = circ * (1 - Math.min(pct, 1))
}
function resetVideoRing() {
    const ring = document.getElementById('videoProgressRing')
    if (ring) {
        const circ = 2 * Math.PI * 105
        ring.style.strokeDashoffset = circ
    }
}

// Создаём видео-плеер в сообщении
    // Внешний контейнер — больше круга, чтобы кольцо было видно
function createVideoPlayer(url, isMe, knownDuration) {
    const outer = document.createElement('div')
    outer.className = 'video-msg-outer'
    outer.style.cssText = 'position:relative;width:216px;height:216px;flex-shrink:0'

    // SVG кольцо — поверх всего, position:absolute
    const r = 100, circ = 2 * Math.PI * r
    const svgNS = 'http://www.w3.org/2000/svg'
    const svg = document.createElementNS(svgNS, 'svg')
    svg.setAttribute('viewBox', '0 0 216 216')
    svg.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;transform:rotate(-90deg);z-index:2;pointer-events:none'

    const bgC = document.createElementNS(svgNS, 'circle')
    bgC.setAttribute('cx','108'); bgC.setAttribute('cy','108'); bgC.setAttribute('r', String(r))
    bgC.setAttribute('fill','none')
    bgC.setAttribute('stroke', isMe ? 'rgba(255,255,255,0.25)' : 'rgba(102,126,234,0.25)')
    bgC.setAttribute('stroke-width','4')

    const fillC = document.createElementNS(svgNS, 'circle')
    fillC.setAttribute('cx','108'); fillC.setAttribute('cy','108'); fillC.setAttribute('r', String(r))
    fillC.setAttribute('fill','none')
    fillC.setAttribute('stroke', isMe ? 'white' : 'var(--accent)')
    fillC.setAttribute('stroke-width','4')
    fillC.setAttribute('stroke-linecap','round')
    fillC.setAttribute('stroke-dasharray', String(circ))
    fillC.setAttribute('stroke-dashoffset', String(circ))
    fillC.style.transition = 'stroke-dashoffset 0.15s linear'

    svg.appendChild(bgC); svg.appendChild(fillC)

    // Круглый видео-элемент внутри
    const circle = document.createElement('div')
    circle.style.cssText = 'position:absolute;inset:8px;border-radius:50%;overflow:hidden;background:transparent;z-index:1'

    const video = document.createElement('video')
    video.src = url; video.playsInline = true; video.preload = 'metadata'
    video.style.cssText = 'width:100%;height:100%;object-fit:cover;display:block'

    // Кнопка Play
    const playBtn = document.createElement('button')
    playBtn.style.cssText = 'position:absolute;inset:0;margin:auto;width:48px;height:48px;border-radius:50%;background:rgba(0,0,0,0.55);color:white;border:none;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);z-index:3;transition:opacity 0.2s'
    playBtn.innerHTML = '<i class="fas fa-play"></i>'

    // Таймер
    const timeEl = document.createElement('span')
    timeEl.style.cssText = 'position:absolute;bottom:14px;left:50%;transform:translateX(-50%);font-size:11px;font-weight:600;color:white;text-shadow:0 1px 4px rgba(0,0,0,0.7);white-space:nowrap;z-index:4;pointer-events:none'
    timeEl.textContent = knownDuration ? fmt(knownDuration) : '0:00'

    let playing = false

    function fmt(s) { s = Math.max(0, Math.floor(s)); return `${Math.floor(s/60)}:${(s%60).toString().padStart(2,'0')}` }

    function updateRing() {
        const dur = (isFinite(video.duration) && video.duration > 0) ? video.duration : (knownDuration || 0)
        if (!dur) return
        const pct = video.currentTime / dur
        fillC.setAttribute('stroke-dashoffset', String(circ * (1 - pct)))
        timeEl.textContent = fmt(dur - video.currentTime)
    }

    video.addEventListener('loadedmetadata', () => {
        const d = isFinite(video.duration) && video.duration > 0 ? video.duration : knownDuration
        if (d) timeEl.textContent = fmt(d)
    })
    video.addEventListener('timeupdate', updateRing)
    video.addEventListener('ended', () => {
        playing = false
        playBtn.innerHTML = '<i class="fas fa-play"></i>'
        video.currentTime = 0
        fillC.setAttribute('stroke-dashoffset', String(circ))
        const endDur = (isFinite(video.duration) && video.duration > 0) ? video.duration : (knownDuration || 0)
        if (endDur) timeEl.textContent = fmt(endDur)
        showPlayBtn()
    })
    video.addEventListener('error', () => {
        playBtn.innerHTML = '<i class="fas fa-exclamation-triangle" style="color:#ff9500;font-size:12px"></i>'
        playBtn.disabled = true
    })

    function showPlayBtn() { playBtn.style.opacity = '1'; playBtn.style.pointerEvents = 'auto' }
    function hidePlayBtn() { playBtn.style.opacity = '0'; playBtn.style.pointerEvents = 'none' }

    playBtn.onclick = (e) => {
        e.stopPropagation()
        if (playing) {
            video.pause(); playing = false
            playBtn.innerHTML = '<i class="fas fa-play"></i>'
            showPlayBtn()
        } else {
            video.play().catch(() => showToast('Ошибка воспроизведения'))
            playing = true
            playBtn.innerHTML = '<i class="fas fa-pause"></i>'
            hidePlayBtn()
        }
    }



    // Перемотка drag по SVG кольцу
    svg.style.pointerEvents = 'auto'
    svg.style.cursor = 'pointer'

    function getAnglePct(e) {
        const rect = outer.getBoundingClientRect()
        const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2
        const ex = e.touches ? e.touches[0].clientX : e.clientX
        const ey = e.touches ? e.touches[0].clientY : e.clientY
        let a = Math.atan2(ex - cx, -(ey - cy))
        if (a < 0) a += 2 * Math.PI
        return a / (2 * Math.PI)
    }

    let scrubbing = false
    let dragStartX = 0, dragStartY = 0, dragMoved = false
    const DRAG_THRESHOLD = 6  // px — меньше этого считается кликом

    svg.style.pointerEvents = 'auto'
    outer.addEventListener('mousedown', (e) => {
        if (e.target === playBtn || e.target.closest('button')) return
        dragStartX = e.clientX; dragStartY = e.clientY; dragMoved = false
        scrubbing = true
        e.preventDefault()
    })
    outer.addEventListener('touchstart', (e) => {
        if (e.target === playBtn || e.target.closest('button')) return
        dragStartX = e.touches[0].clientX; dragStartY = e.touches[0].clientY; dragMoved = false
        scrubbing = true
        e.preventDefault()
    }, { passive: false })
    let pendingSeek = null
    const onMove = (e) => {
        if (!scrubbing || !video.duration) return
        const mx = e.touches ? e.touches[0].clientX : e.clientX
        const my = e.touches ? e.touches[0].clientY : e.clientY
        // Проверяем порог — только тогда считаем drag
        if (!dragMoved) {
            const dx = mx - dragStartX, dy = my - dragStartY
            if (Math.sqrt(dx*dx + dy*dy) < DRAG_THRESHOLD) return
            dragMoved = true
            if (playing) { video.pause(); playing = false; playBtn.innerHTML = '<i class="fas fa-play"></i>' }
        }
        e.preventDefault()
        const pct = getAnglePct(e)
        fillC.setAttribute('stroke-dashoffset', String(circ * (1 - pct)))
        timeEl.textContent = fmt(Math.max(0, video.duration * (1 - pct)))
        if (pendingSeek !== null) return
        pendingSeek = pct
        setTimeout(() => {
            if (video.duration) {
                const t = pendingSeek * video.duration
                if (video.fastSeek) video.fastSeek(t)
                else video.currentTime = t
            }
            pendingSeek = null
        }, 80)
    }
    const onUp = () => {
        if (!scrubbing) return
        scrubbing = false
        if (!dragMoved) {
            // Клик на кружок — пауза если играло, показываем кнопку
            if (playing) {
                video.pause()
                playing = false
                playBtn.innerHTML = '<i class="fas fa-play"></i>'
            }
            showPlayBtn()
        }
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
    document.addEventListener('touchmove', onMove, { passive: false })
    document.addEventListener('touchend', onUp)

    circle.appendChild(video)
    outer.appendChild(circle)
    outer.appendChild(svg)
    outer.appendChild(playBtn)
    outer.appendChild(timeEl)
    return outer
}

window.openVideoRecorder  = openVideoRecorder
window.closeVideoRecorder = closeVideoRecorder
window.toggleVideoRecord  = toggleVideoRecord
window.retakeVideo        = retakeVideo
window.sendVideoMessage   = sendVideoMessage
// Глобальные функции для HTML
window.toggleSidebar = toggleSidebar
window.closeChat = closeChat
function toggleProfileMenu(e) {
    e.stopPropagation()
    const menu = document.getElementById('profileDropdownMenu')
    if (menu.style.display === 'block') {
        menu.style.display = 'none'
        return
    }
    menu.style.display = 'block'
    const close = () => { menu.style.display = 'none'; document.removeEventListener('click', close) }
    setTimeout(() => document.addEventListener('click', close), 0)
}

function openChatThemeFromProfile() {
    document.getElementById('profileDropdownMenu').style.display = 'none'
    closeModal()
    // Небольшая задержка чтобы модалка закрылась
    setTimeout(() => openChatThemeModal(), 200)
}

function blockFromProfile() {
    document.getElementById('profileDropdownMenu').style.display = 'none'
    const phone = document.getElementById('profileModal')._profilePhone
    if (phone) { closeModal(); blockUser(phone) }
}

window.toggleProfileMenu = toggleProfileMenu
window.openChatThemeFromProfile = openChatThemeFromProfile
window.blockFromProfile = blockFromProfile

window.openChatProfile = openChatProfile
window.openMyProfile = openMyProfile
window.send = send
window.showRegisterForm = showRegisterForm
window.showLoginForm = showLoginForm
window.register = register
window.login = login
window.savePasswordForExisting = savePasswordForExisting
window.closePasswordSetup = closePasswordSetup
window.openSettings = openSettings
window.closeSettings = closeSettings
window.savePhonePrivacy = savePhonePrivacy
window.saveOnlinePrivacy = saveOnlinePrivacy
window.saveAvatarPrivacy = saveAvatarPrivacy
window.openBlockedUsers = openBlockedUsers
window.openSessions = openSessions
window.clearAllChats = clearAllChats
window.exportData = exportData
window.openChangePassword = openChangePassword
window.closeChangePassword = closeChangePassword
window.changePassword = changePassword
window.removeAvatar = removeAvatar
window.zoomIn = zoomIn
window.zoomOut = zoomOut
window.rotateLeft = rotateLeft
window.rotateRight = rotateRight
window.saveCroppedAvatar = saveCroppedAvatar
window.closeAvatarEditor = closeAvatarEditor
function addReactionFromMenu() {
    if (!selectedMessageId) return
    const id = selectedMessageId
    hideContextMenus()
    // Небольшая задержка чтобы меню успело скрыться
    setTimeout(() => showReactionsPanel(null, id), 50)
}
window.addReactionFromMenu = addReactionFromMenu
window.deleteMessage = deleteMessage
window.deleteChat = deleteChat
window.muteChat = muteChat
window.clearChat = clearChat
window.saveVoiceMode = saveVoiceMode
window.saveCameraSettings = saveCameraSettings
window.toggleStickerModal = toggleStickerModal
window.closeStickerModal = closeStickerModal
window.switchStickerTab = switchStickerTab
window.sendSticker = sendSticker
window.uploadStickers = uploadStickers
window.importTgStickers = importTgStickers
window.previewTgPack = previewTgPack
window.importTgPack = importTgPack
window.cancelTgImport = cancelTgImport
window.insertEmoji = insertEmoji
window.renderEmojiGrid = renderEmojiGrid
window.forwardMessage = forwardMessage
window.closeForwardModal = closeForwardModal
window.clearChat = clearChat
window.saveVoiceMode = saveVoiceMode
window.saveCameraSettings = saveCameraSettings
window.deleteSticker = deleteSticker
window.showReactionsPanel = showReactionsPanel
window.addReaction = addReaction

// ============= СИСТЕМА ТЕМ =============

const THEMES = [
    {
        id: 'default', name: 'Ночной', emoji: '🌙',
        sidebar: 'linear-gradient(170deg,#1c3a47 0%,#1e424f 60%,#1a3d4a 100%)',
        accent: '#0A84FF', bubble: '#0A84FF', bg: '#f2f2f7'
    },
    {
        id: 'mesh', name: 'Закат', emoji: '🌅',
        sidebar: '#1e2a35; background-image: radial-gradient(ellipse at 15% 60%,#1a3a5c 0%,transparent 55%),radial-gradient(ellipse at 80% 20%,#5c2a2a 0%,transparent 50%),radial-gradient(ellipse at 70% 75%,#7a2e2e 0%,transparent 45%)',
        accent: '#FF6B6B', bubble: '#c0392b', bg: '#f2f2f7'
    },
    {
        id: 'forest', name: 'Лес', emoji: '🌲',
        sidebar: 'linear-gradient(170deg,#1a2f1a 0%,#1e3d1e 60%,#162b16 100%)',
        accent: '#30d158', bubble: '#1a7a3a', bg: '#f0f4f0'
    },
    {
        id: 'lavender', name: 'Лаванда', emoji: '💜',
        sidebar: 'linear-gradient(170deg,#2a1a3e 0%,#352050 60%,#2a1a3e 100%)',
        accent: '#BF5AF2', bubble: '#7B2FBE', bg: '#f5f0ff'
    },
    {
        id: 'rose', name: 'Розовый', emoji: '🌸',
        sidebar: 'linear-gradient(170deg,#3d1a2a 0%,#4f1e35 60%,#3d1a2a 100%)',
        accent: '#FF375F', bubble: '#c0185f', bg: '#fff0f4'
    },
    {
        id: 'gold', name: 'Золото', emoji: '✨',
        sidebar: 'linear-gradient(170deg,#2a220a 0%,#3d3210 60%,#2a220a 100%)',
        accent: '#FFD60A', bubble: '#b8860b', bg: '#fffbf0'
    },
]

const ACCENT_COLORS = [
    '#0A84FF','#30d158','#FF375F','#FF9F0A','#BF5AF2','#FF6B35','#00C7BE','#FF3B30',
]

const MY_BUBBLE_COLORS = [
    '#0A84FF','#30d158','#c0392b','#8e44ad','#e67e22','#16a085','#2980b9','#1a1a2e',
]

const WALLPAPERS = [
    { id: 'none',    name: 'Нет',     preview: '#f2f2f7', type: 'color', value: '#f2f2f7' },
    { id: 'dark',    name: 'Тёмный',  preview: '#1c1c1e', type: 'color', value: '#1c1c1e' },
    { id: 'dots',    name: 'Точки',   preview: '#f5f5f5', type: 'pattern', value: 'dots' },
    { id: 'grid',    name: 'Сетка',   preview: '#f0f0f0', type: 'pattern', value: 'grid' },
    { id: 'waves',   name: 'Волны',   preview: '#e8f4f8', type: 'pattern', value: 'waves' },
    { id: 'mesh1',   name: 'Меш 1',   preview: 'linear-gradient(135deg,#667eea,#764ba2)', type: 'gradient', value: 'linear-gradient(135deg,#1a1a2e,#16213e,#0f3460)' },
    { id: 'mesh2',   name: 'Рассвет', preview: 'linear-gradient(135deg,#f093fb,#f5576c)', type: 'gradient', value: 'linear-gradient(135deg,#2d1b69,#11998e)' },
    { id: 'mesh3',   name: 'Океан',   preview: 'linear-gradient(135deg,#4facfe,#00f2fe)', type: 'gradient', value: 'linear-gradient(160deg,#0d1b2a,#1b4332,#0d1b2a)' },
]

let currentTheme = {}
let pendingWallpaper = null

// ── Инициализация ────────────────────────────────────────────
async function loadTheme() {
    if (!currentUser) return
    try {
        // Сначала localStorage для быстрого применения
        const local = localStorage.getItem('theme_' + currentUser)
        if (local) applyTheme(JSON.parse(local))

        // Потом сервер
        const res = await fetch(`/api/theme/${encodeURIComponent(currentUser)}`)
        const data = await res.json()
        if (data.theme && Object.keys(data.theme).length) {
            currentTheme = data.theme
            applyTheme(currentTheme)
            localStorage.setItem('theme_' + currentUser, JSON.stringify(currentTheme))
        }
    } catch(e) { console.warn('loadTheme error:', e) }
}

function applyTheme(theme) {
    if (!theme) return
    const root = document.documentElement

    if (theme.accent)  root.style.setProperty('--accent', theme.accent)
    if (theme.sidebar) {
        const sidebar = document.querySelector('.sidebar')
        if (sidebar) sidebar.style.background = theme.sidebar
    }
    if (theme.bubble) {
        root.style.setProperty('--bubble-me', theme.bubble)
        // Динамически обновляем CSS для .message.me
        let styleEl = document.getElementById('dynamic-theme-style')
        if (!styleEl) {
            styleEl = document.createElement('style')
            styleEl.id = 'dynamic-theme-style'
            document.head.appendChild(styleEl)
        }
        styleEl.textContent = `
            .message.me:not(.me-video) { background: ${theme.bubble} !important; }
            .message.me-video { background: none !important; box-shadow: none !important; padding: 0 !important; }
            .voice-player.me, .message.me .voice-player { background: ${theme.bubble} !important; }
            .send-btn, .voice-send-btn { background: ${theme.accent || 'var(--accent)'} !important; }
            .voice-btn, .video-msg-btn { color: ${theme.accent || 'var(--accent)'} !important; }
            .unread-badge { background: ${theme.accent || 'var(--accent)'} !important; }
            .chatItem.active { background: ${theme.accent || 'var(--accent)'}22 !important; }
        `
    }
    if (theme.wallpaper) {
        // Применяем глобальные обои только если у чата нет своей темы
        if (!currentChat || !chatThemes[currentChat]?.wallpaper) {
            applyWallpaper(theme.wallpaper)
        }
    }
}

function applyWallpaper(wp) {
    const messagesEl = document.getElementById('messages')
    if (!messagesEl) return
    if (!wp || wp.type === 'color') {
        messagesEl.style.background = wp?.value || '#f2f2f7'
        messagesEl.style.backgroundImage = ''
    } else if (wp.type === 'gradient') {
        messagesEl.style.background = wp.value
        messagesEl.style.backgroundImage = ''
    } else if (wp.type === 'pattern') {
        const patterns = {
            dots:  { bg: '#f8f8f8', img: 'radial-gradient(circle,#00000015 1px,transparent 1px)', size: '20px 20px' },
            grid:  { bg: '#f8f8f8', img: 'linear-gradient(#0000000a 1px,transparent 1px),linear-gradient(90deg,#0000000a 1px,transparent 1px)', size: '24px 24px' },
            waves: { bg: '#e8f4f8', img: 'repeating-linear-gradient(45deg,#00000008 0,#00000008 1px,transparent 0,transparent 50%)', size: '10px 10px' },
        }
        const p = patterns[wp.value] || patterns.dots
        messagesEl.style.background = p.bg
        messagesEl.style.backgroundImage = p.img
        messagesEl.style.backgroundSize = p.size
    } else if (wp.type === 'image') {
        messagesEl.style.backgroundImage = `url(${wp.value})`
        messagesEl.style.backgroundSize = 'cover'
        messagesEl.style.backgroundPosition = 'center'
    }
}

// ── Открытие модалки тем ─────────────────────────────────────
function openThemeModal() {
    const modal = document.getElementById('themeModal')
    modal.style.display = 'flex'
    renderThemePresets()
    renderAccentSwatches()
    renderBubbleSwatches()
}
function closeThemeModal() {
    document.getElementById('themeModal').style.display = 'none'
}

function renderThemePresets() {
    const container = document.getElementById('themePresets')
    container.innerHTML = ''
    THEMES.forEach(t => {
        const el = document.createElement('div')
        el.className = 'theme-preset-item' + (currentTheme.id === t.id ? ' active' : '')
        el.innerHTML = `<div class="preset-preview" style="background:${t.sidebar.split(';')[0]}"></div><span>${t.emoji} ${t.name}</span>`
        el.onclick = () => {
            document.querySelectorAll('.theme-preset-item').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            currentTheme = { ...currentTheme, ...t }
            previewTheme(currentTheme)
        }
        container.appendChild(el)
    })
}

function renderAccentSwatches() {
    const container = document.getElementById('accentSwatches')
    container.innerHTML = ''
    ACCENT_COLORS.forEach(color => {
        const el = document.createElement('div')
        el.className = 'color-swatch' + (currentTheme.accent === color ? ' active' : '')
        el.style.background = color
        el.onclick = () => {
            document.querySelectorAll('#accentSwatches .color-swatch').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            document.getElementById('accentColorPicker').value = color
            previewAccent(color)
        }
        container.appendChild(el)
    })
}

function renderBubbleSwatches() {
    const container = document.getElementById('myBubbleSwatches')
    container.innerHTML = ''
    MY_BUBBLE_COLORS.forEach(color => {
        const el = document.createElement('div')
        el.className = 'color-swatch' + (currentTheme.bubble === color ? ' active' : '')
        el.style.background = color
        el.onclick = () => {
            document.querySelectorAll('#myBubbleSwatches .color-swatch').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            document.getElementById('myBubblePicker').value = color
            previewBubble('me', color)
        }
        container.appendChild(el)
    })
}

function previewAccent(color) {
    currentTheme.accent = color
    previewTheme(currentTheme)
}
function previewBubble(who, color) {
    currentTheme.bubble = color
    previewTheme(currentTheme)
}
function previewTheme(theme) {
    // Обновляем предпросмотр в модалке
    const msgs = document.querySelectorAll('#themePreviewChat .theme-preview-msg.me')
    msgs.forEach(m => m.style.background = theme.bubble || '#0A84FF')
    const root = document.documentElement
    if (theme.accent) root.style.setProperty('--preview-accent', theme.accent)
}

async function saveTheme() {
    applyTheme(currentTheme)
    localStorage.setItem('theme_' + currentUser, JSON.stringify(currentTheme))
    try {
        await fetch(`/api/theme/${encodeURIComponent(currentUser)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentTheme)
        })
    } catch(e) {}
    // Перезаписываем обои в текущем чате если у него нет своей темы
    if (currentChat && !chatThemes[currentChat]?.wallpaper) {
        applyWallpaper(currentTheme.wallpaper || null)
    }
    showToast('Тема применена ✓')
    closeThemeModal()
}

// ── Обои ─────────────────────────────────────────────────────
function openWallpaperModal() {
    const modal = document.getElementById('wallpaperModal')
    modal.style.display = 'flex'
    renderWallpaperGrid()
}
function closeWallpaperModal() {
    document.getElementById('wallpaperModal').style.display = 'none'
}

function renderWallpaperGrid() {
    const grid = document.getElementById('wallpaperGrid')
    grid.innerHTML = ''
    WALLPAPERS.forEach(wp => {
        const el = document.createElement('div')
        el.className = 'wallpaper-item' + (currentTheme.wallpaper?.id === wp.id ? ' active' : '')
        el.style.background = wp.preview
        el.innerHTML = `<span>${wp.name}</span>`
        el.onclick = () => {
            document.querySelectorAll('.wallpaper-item').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            pendingWallpaper = { id: wp.id, type: wp.type, value: wp.value }
            applyWallpaper(pendingWallpaper)
        }
        grid.appendChild(el)
    })
}

function handleWallpaperUpload(input) {
    const file = input.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = e => {
        pendingWallpaper = { id: 'custom', type: 'image', value: e.target.result }
        applyWallpaper(pendingWallpaper)
    }
    reader.readAsDataURL(file)
}

async function saveWallpaper() {
    if (!pendingWallpaper) {
        closeWallpaperModal()
        return
    }
    currentTheme.wallpaper = pendingWallpaper
    localStorage.setItem('theme_' + currentUser, JSON.stringify(currentTheme))
    try {
        // Не сохраняем base64 изображения на сервере — слишком большие
        const serverTheme = { ...currentTheme }
        if (serverTheme.wallpaper?.type === 'image') serverTheme.wallpaper = { id: 'custom', type: 'color', value: '#1c1c1e' }
        await fetch(`/api/theme/${encodeURIComponent(currentUser)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(serverTheme)
        })
    } catch(e) {}
    showToast('Обои применены ✓')
    closeWallpaperModal()
}

window.openThemeModal    = openThemeModal
window.closeThemeModal   = closeThemeModal
window.openWallpaperModal  = openWallpaperModal
window.closeWallpaperModal = closeWallpaperModal
window.saveTheme         = saveTheme
window.saveWallpaper     = saveWallpaper
window.previewAccent     = previewAccent
window.previewBubble     = previewBubble
window.handleWallpaperUpload = handleWallpaperUpload

// ── Загрузка тем чатов с сервера ────────────────────────────
async function loadChatThemesFromServer() {
    try {
        const res = await fetch(`/api/theme/${encodeURIComponent(currentUser + '_chats')}`)
        const data = await res.json()
        if (data.theme && Object.keys(data.theme).length) {
            Object.entries(data.theme).forEach(([phone, theme]) => {
                const key = `chat_theme_${currentUser}_${phone}`
                if (!localStorage.getItem(key)) {
                    localStorage.setItem(key, JSON.stringify(theme))
                }
            })
        }
    } catch(e) {}
}

// ============= ТЕМА ЧАТА =============

let pendingChatTheme = {}

function getChatThemeKey(phone) {
    return `chat_theme_${currentUser}_${phone}`
}

function applyChatTheme(theme) {
    if (!theme) return
    const messagesEl = document.getElementById('messages')
    if (!messagesEl) return
    // Обои
    if (theme.wallpaper) {
        applyWallpaper(theme.wallpaper)
    } else if (currentTheme?.wallpaper) {
        applyWallpaper(currentTheme.wallpaper)
    } else {
        messagesEl.style.background = ''
        messagesEl.style.backgroundImage = ''
        messagesEl.style.backgroundSize = ''
    }
    // Цвет пузырьков
    let chatStyle = document.getElementById('chat-theme-style')
    if (!chatStyle) {
        chatStyle = document.createElement('style')
        chatStyle.id = 'chat-theme-style'
        document.head.appendChild(chatStyle)
    }
    if (theme.bubble) {
        chatStyle.textContent = `.message.me:not(.me-video) { background: ${theme.bubble} !important; }`
    } else if (currentTheme?.bubble) {
        chatStyle.textContent = `.message.me:not(.me-video) { background: ${currentTheme.bubble} !important; }`
    } else {
        chatStyle.textContent = ''
    }
}

function loadChatTheme(phone) {
    if (!phone) return
    try {
        const saved = localStorage.getItem(getChatThemeKey(phone))
        if (saved) applyChatTheme(JSON.parse(saved))
        else resetChatThemeStyles()
    } catch(e) {}
}



function resetChatThemeStyles() {
    const chatStyle = document.getElementById('chat-theme-style')
    if (chatStyle) chatStyle.textContent = ''
    if (currentTheme?.wallpaper) applyWallpaper(currentTheme.wallpaper)
    else {
        const messagesEl = document.getElementById('messages')
        if (messagesEl) { messagesEl.style.background = ''; messagesEl.style.backgroundImage = '' }
    }
}

// ── Открытие модалки ─────────────────────────────────────────
function openChatThemeModal() {
    const phone = selectedChatPhone || currentChat
    hideContextMenus()
    if (!phone) return
    const modal = document.getElementById('chatThemeModal')
    // Сохраняем телефон прямо в DOM — не зависит от глобальных переменных
    modal.dataset.chatPhone = phone
    modal.style.display = 'flex'

    try {
        const saved = localStorage.getItem(getChatThemeKey(phone))
        pendingChatTheme = saved ? JSON.parse(saved) : {}
    } catch(e) { pendingChatTheme = {} }

    renderChatBubbleSwatches()
    renderChatWallpaperGrid()
    updateChatThemePreview()
}

function getChatThemePhone() {
    return document.getElementById('chatThemeModal')?.dataset?.chatPhone || null
}

function closeChatThemeModal() {
    const modal = document.getElementById('chatThemeModal')
    const phone = modal?.dataset?.chatPhone
    modal.style.display = 'none'
    if (phone && phone === currentChat) loadChatTheme(currentChat)
    pendingChatTheme = {}
    if (modal) delete modal.dataset.chatPhone
}

function renderChatBubbleSwatches() {
    const container = document.getElementById('chatBubbleSwatches')
    container.innerHTML = ''
    MY_BUBBLE_COLORS.forEach(color => {
        const el = document.createElement('div')
        el.className = 'color-swatch' + (pendingChatTheme.bubble === color ? ' active' : '')
        el.style.background = color
        el.onclick = () => {
            container.querySelectorAll('.color-swatch').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            document.getElementById('chatBubblePicker').value = color
            previewChatBubble(color)
        }
        container.appendChild(el)
    })
    if (pendingChatTheme.bubble) {
        document.getElementById('chatBubblePicker').value = pendingChatTheme.bubble
    }
}

function renderChatWallpaperGrid() {
    const grid = document.getElementById('chatWallpaperGrid')
    grid.innerHTML = ''
    WALLPAPERS.forEach(wp => {
        const el = document.createElement('div')
        el.className = 'wallpaper-item' + (pendingChatTheme.wallpaper?.id === wp.id ? ' active' : '')
        el.style.background = wp.preview
        el.innerHTML = `<span>${wp.name}</span>`
        el.onclick = () => {
            grid.querySelectorAll('.wallpaper-item').forEach(x => x.classList.remove('active'))
            el.classList.add('active')
            pendingChatTheme.wallpaper = { id: wp.id, type: wp.type, value: wp.value }
            updateChatThemePreview()
        }
        grid.appendChild(el)
    })
}

function previewChatBubble(color) {
    pendingChatTheme.bubble = color
    updateChatThemePreview()
}

function previewChatWallpaper(type, value) {
    pendingChatTheme.wallpaper = { id: 'custom', type, value }
    updateChatThemePreview()
}

function handleChatWallpaperUpload(input) {
    const file = input.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = e => {
        pendingChatTheme.wallpaper = { id: 'custom', type: 'image', value: e.target.result }
        updateChatThemePreview()
    }
    reader.readAsDataURL(file)
}

function updateChatThemePreview() {
    const preview = document.getElementById('chatThemePreview')
    if (preview) {
        // Обои в превью-блоке модалки
        if (pendingChatTheme.wallpaper) {
            const wp = pendingChatTheme.wallpaper
            if (wp.type === 'color') {
                preview.style.background = wp.value
                preview.style.backgroundImage = ''
            } else if (wp.type === 'gradient') {
                preview.style.background = wp.value
                preview.style.backgroundImage = ''
            } else if (wp.type === 'image') {
                preview.style.background = ''
                preview.style.backgroundImage = `url(${wp.value})`
                preview.style.backgroundSize = 'cover'
                preview.style.backgroundPosition = 'center'
            } else if (wp.type === 'pattern') {
                const patterns = {
                    dots:  { bg:'#f8f8f8', img:'radial-gradient(circle,#00000015 1px,transparent 1px)', size:'20px 20px' },
                    grid:  { bg:'#f8f8f8', img:'linear-gradient(#0000000a 1px,transparent 1px),linear-gradient(90deg,#0000000a 1px,transparent 1px)', size:'24px 24px' },
                    waves: { bg:'#e8f4f8', img:'repeating-linear-gradient(45deg,#00000008 0,#00000008 1px,transparent 0,transparent 50%)', size:'10px 10px' },
                }
                const p = patterns[wp.value] || patterns.dots
                preview.style.background = p.bg
                preview.style.backgroundImage = p.img
                preview.style.backgroundSize = p.size
            }
        } else {
            preview.style.cssText = ''
        }
        // Цвет пузырьков в превью
        preview.querySelectorAll('.theme-preview-msg.me').forEach(m => {
            m.style.background = pendingChatTheme.bubble || 'var(--accent)'
        })
    }

    // Live preview — применяем к реальному чату если это текущий чат
    const _phone = getChatThemePhone()
    if (_phone && _phone === currentChat) applyChatTheme(pendingChatTheme)
}

async function saveChatTheme() {
    const phone = getChatThemePhone()
    if (!phone) { showToast('Ошибка: чат не определён'); return }
    localStorage.setItem(getChatThemeKey(phone), JSON.stringify(pendingChatTheme))
    if (phone === currentChat) applyChatTheme(pendingChatTheme)
    // Сохраняем на сервер
    try {
        const allChatThemes = {}
        // Собираем все сохранённые темы чатов из localStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i)
            const prefix = `chat_theme_${currentUser}_`
            if (key && key.startsWith(prefix)) {
                const phone = key.slice(prefix.length)
                try { allChatThemes[phone] = JSON.parse(localStorage.getItem(key)) } catch(e) {}
            }
        }
        // Убираем base64 изображения
        Object.values(allChatThemes).forEach(t => {
            if (t?.wallpaper?.type === 'image') t.wallpaper = { id:'custom', type:'color', value:'#1c1c1e' }
        })
        await fetch(`/api/theme/${encodeURIComponent(currentUser + '_chats')}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(allChatThemes)
        })
    } catch(e) { console.warn('saveChatTheme server error:', e) }
    showToast('Тема чата применена ✓')
    closeChatThemeModal()
}

async function resetChatTheme() {
    const phone = getChatThemePhone()
    if (!phone) return
    localStorage.removeItem(getChatThemeKey(phone))
    if (phone === currentChat) resetChatThemeStyles()
    // Синкаем с сервером
    try {
        const allChatThemes = {}
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i)
            const prefix = `chat_theme_${currentUser}_`
            if (key && key.startsWith(prefix)) {
                const phone = key.slice(prefix.length)
                try { allChatThemes[phone] = JSON.parse(localStorage.getItem(key)) } catch(e) {}
            }
        }
        await fetch(`/api/theme/${encodeURIComponent(currentUser + '_chats')}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(allChatThemes)
        })
    } catch(e) {}
    closeChatThemeModal()
    selectedChatPhone = null
    showToast('Тема чата сброшена')
}

window.openChatThemeModal  = openChatThemeModal
window.closeChatThemeModal = closeChatThemeModal
window.saveChatTheme       = saveChatTheme
window.resetChatTheme      = resetChatTheme
window.previewChatBubble   = previewChatBubble
window.previewChatWallpaper = previewChatWallpaper
window.handleChatWallpaperUpload = handleChatWallpaperUpload

// ============= JAMENDO МУЗЫКАЛЬНЫЙ ПЛЕЕР =============

let currentTrack = null
let musicPlaying = false
let musicSearchTimeout = null
let musicTracks = []

const audio = () => document.getElementById('jamendoAudio')

function openMusicPlayer() {
    const modal = document.getElementById('musicPlayerModal')
    modal.style.display = 'flex'
    if (!musicTracks.length) loadTrendingTracks()
}
function closeMusicPlayer() {
    document.getElementById('musicPlayerModal').style.display = 'none'
}

async function loadTrendingTracks() {
    showMusicLoading(true)
    try {
        const res = await fetch('/api/jamendo/trending?limit=30')
        const data = await res.json()
        if (data.ok) renderTrackList(data.tracks)
        else showToast('Jamendo недоступен — добавьте JAMENDO_CLIENT_ID')
    } catch(e) {
        showToast('Ошибка загрузки музыки')
    }
    showMusicLoading(false)
}

function onMusicSearch(q) {
    clearTimeout(musicSearchTimeout)
    document.getElementById('musicSearchClear').style.display = q ? 'block' : 'none'
    if (!q) { loadTrendingTracks(); return }
    musicSearchTimeout = setTimeout(async () => {
        showMusicLoading(true)
        try {
            const res = await fetch(`/api/jamendo/search?q=${encodeURIComponent(q)}&limit=30`)
            const data = await res.json()
            if (data.ok) renderTrackList(data.tracks)
        } catch(e) {}
        showMusicLoading(false)
    }, 400)
}

function clearMusicSearch() {
    document.getElementById('musicSearchInput').value = ''
    document.getElementById('musicSearchClear').style.display = 'none'
    loadTrendingTracks()
}

function renderTrackList(tracks) {
    musicTracks = tracks
    const list = document.getElementById('musicTrackList')
    list.innerHTML = ''
    if (!tracks.length) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-secondary)">Ничего не найдено</div>'
        return
    }
    tracks.forEach((t, i) => {
        const el = document.createElement('div')
        el.className = 'music-track-item' + (currentTrack?.id === t.id ? ' active' : '')
        const dur = t.duration ? `${Math.floor(t.duration/60)}:${(t.duration%60).toString().padStart(2,'0')}` : '0:30'
        el.innerHTML = `
            <img src="${t.image || ''}" onerror="this.style.display='none'" class="music-track-cover">
            <div class="music-track-info">
                <div class="music-track-title">${escapeHtml(t.name)}</div>
                <div class="music-track-artist">${escapeHtml(t.artist_name)} · <span style="opacity:0.7">${dur}</span></div>
            </div>
            <div class="music-track-actions">
                <button class="music-mini-btn" onclick="playTrack(${i})" title="Играть">
                    <i class="fas fa-${currentTrack?.id === t.id && musicPlaying ? 'pause' : 'play'}"></i>
                </button>
                <button class="music-mini-btn" onclick="shareMusicTrackById(${i})" title="Поделиться">
                    <i class="fas fa-share"></i>
                </button>
            </div>`
        list.appendChild(el)
    })
}

function showMusicLoading(show) {
    document.getElementById('musicLoading').style.display = show ? 'flex' : 'none'
}

function playTrack(idx) {
    const track = musicTracks[idx]
    if (!track?.audio) { showToast('Нет превью для этого трека'); return }

    currentTrack = track
    musicPlaying = true

    // Обновляем UI плеера
    document.getElementById('musicNowPlaying').style.display = 'flex'
    document.getElementById('musicProgress').style.display = 'block'
    document.getElementById('musicCover').src = track.image || ''
    document.getElementById('musicTrackName').textContent = track.name
    document.getElementById('musicArtistName').textContent = track.artist_name
    document.getElementById('musicPlayBtn').innerHTML = '<i class="fas fa-pause"></i>'

    // Аудио
    const a = audio()
    a.src = track.audio
    a.play().catch(() => showToast('Ошибка воспроизведения'))

    // Обновляем список
    renderTrackList(musicTracks)

    // Статус "слушает"
    updateMusicStatus(track, true)
}

function toggleMusicPlay() {
    const a = audio()
    if (musicPlaying) {
        a.pause()
        musicPlaying = false
        document.getElementById('musicPlayBtn').innerHTML = '<i class="fas fa-play"></i>'
        updateMusicStatus(currentTrack, false)
    } else {
        a.play()
        musicPlaying = true
        document.getElementById('musicPlayBtn').innerHTML = '<i class="fas fa-pause"></i>'
        updateMusicStatus(currentTrack, true)
    }
}

function initMusicAudio() {
    const a = document.getElementById('jamendoAudio')
    if (!a) return
    a.addEventListener('timeupdate', () => {
        if (!a.duration) return
        const pct = (a.currentTime / a.duration) * 100
        const fill = document.getElementById('musicProgressFill')
        const cur  = document.getElementById('musicCurrentTime')
        const dur  = document.getElementById('musicDuration')
        if (fill) fill.style.width = pct + '%'
        if (cur)  cur.textContent  = fmtTime(a.currentTime)
        if (dur)  dur.textContent  = fmtTime(a.duration)
    })
    a.addEventListener('ended', () => {
        musicPlaying = false
        const btn = document.getElementById('musicPlayBtn')
        if (btn) btn.innerHTML = '<i class="fas fa-play"></i>'
        updateMusicStatus(currentTrack, false)
    })
}

function seekMusic(e) {
    const bar = document.getElementById('musicProgressBar')
    const pct = (e.clientX - bar.getBoundingClientRect().left) / bar.offsetWidth
    const a = audio()
    if (a.duration) a.currentTime = a.duration * pct
}

function fmtTime(s) {
    s = Math.floor(s || 0)
    return `${Math.floor(s/60)}:${(s%60).toString().padStart(2,'0')}`
}

// Поделиться треком в чат
function shareMusicTrack() { if (currentTrack) shareMusicTrackObj(currentTrack) }
function shareMusicTrackById(idx) { shareMusicTrackObj(musicTracks[idx]) }

function shareMusicTrackObj(track) {
    if (!currentChat) { showToast('Выберите чат'); return }
    const msg = `[MUSIC]${JSON.stringify({
        id: track.id,
        name: track.name,
        artist: track.artist_name,
        cover: track.image,
        audio: track.audio,
        url: track.shareurl,
        duration: track.duration || 0
    })}[/MUSIC]`
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ action: 'send', to: currentChat, text: msg }))
        showToast('Трек отправлен в чат 🎵')
        closeMusicPlayer()
    }
}

// Статус "слушает"
async function updateMusicStatus(track, isPlaying) {
    if (!currentUser || !track) return
    try {
        await fetch(`/api/music-status/${encodeURIComponent(currentUser)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                track_id: track.id,
                track_name: track.name,
                artist_name: track.artist_name,
                cover_url: track.image || '',
                preview_url: track.audio || '',
                jamendo_url: track.shareurl || '',
                duration: track.duration || 0,
                is_playing: isPlaying
            })
        })
    } catch(e) {}
}

// Рендер музыкальной карточки в чате
function createMusicCard(data, isMe) {
    const wrap = document.createElement('div')
    wrap.className = `music-card ${isMe ? 'me' : 'other'}`

    let isPlaying = false
    const audioEl = new Audio(data.audio)

    wrap.innerHTML = `
        <img class="music-card-cover" src="${data.cover || ''}" onerror="this.style.display='none'">
        <div class="music-card-info">
            <div class="music-card-name">${escapeHtml(data.name)}</div>
            <div class="music-card-artist">${escapeHtml(data.artist)}</div>
            <div class="music-card-label">Deezer · 30 сек превью</div>
        </div>
        <button class="music-card-play"><i class="fas fa-play"></i></button>`

    const btn = wrap.querySelector('.music-card-play')
    btn.onclick = () => {
        if (isPlaying) {
            audioEl.pause()
            btn.innerHTML = '<i class="fas fa-play"></i>'
        } else {
            // Останавливаем другие
            document.querySelectorAll('.music-card-play').forEach(b => {
                if (b !== btn) b.innerHTML = '<i class="fas fa-play"></i>'
            })
            audioEl.play().catch(() => showToast('Ошибка воспроизведения'))
            btn.innerHTML = '<i class="fas fa-pause"></i>'
        }
        isPlaying = !isPlaying
    }
    audioEl.addEventListener('ended', () => {
        isPlaying = false
        btn.innerHTML = '<i class="fas fa-play"></i>'
    })

    return wrap
}

window.openMusicPlayer  = openMusicPlayer
window.closeMusicPlayer = closeMusicPlayer
window.onMusicSearch    = onMusicSearch
window.clearMusicSearch = clearMusicSearch
window.playTrack        = playTrack
window.toggleMusicPlay  = toggleMusicPlay
window.seekMusic        = seekMusic
window.shareMusicTrack  = shareMusicTrack
window.shareMusicTrackById = shareMusicTrackById
