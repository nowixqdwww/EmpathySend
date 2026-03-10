let ws
let currentUser = null
let currentChat = null
let reconnectAttempts = 0
const maxReconnectAttempts = 10
let currentUserProfile = null
let typingTimeout = null
let reconnectTimeout = null
let pingInterval = null
let isConnected = false

// Показ уведомлений
function showToast(message, duration = 3000) {
    const toast = document.getElementById('toast')
    toast.textContent = message
    toast.classList.add('show')

    setTimeout(() => {
        toast.classList.remove('show')
    }, duration)
}

// Форматирование номера телефона
function formatPhone(phone) {
    if (!phone) return 'Нет номера'
    // Простое форматирование для российских номеров
    if (phone.length === 11) {
        return phone.replace(/(\d{1})(\d{3})(\d{3})(\d{2})(\d{2})/, '+$1 ($2) $3-$4-$5')
    }
    return phone
}

// Получение первой буквы для аватара
function getAvatarLetter(name) {
    if (!name) return '👤'
    // Если есть username с @
    if (name.startsWith('@') && name.length > 1) {
        return name[1].toUpperCase()
    }
    // Обычное имя
    if (name.length > 0) {
        return name[0].toUpperCase()
    }
    return '👤'
}

// Экранирование HTML
function escapeHtml(text) {
    const div = document.createElement('div')
    div.textContent = text
    return div.innerHTML
}

// Переключение сайдбара на мобильных
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar')
    sidebar.classList.toggle('open')
}

// Закрыть чат на мобильных
function closeChat(event) {
    if (event) event.stopPropagation()
    currentChat = null
    document.getElementById('emptyChat').style.display = 'flex'
    document.getElementById('chatBlock').style.display = 'none'
    document.getElementById('sidebar').classList.add('open')
}

// Вход в приложение
function login() {
    const phone = document.getElementById("loginPhone").value.trim()

    if (!phone) {
        showToast("Введите номер телефона")
        return
    }

    if (phone.length < 10) {
        showToast("Номер телефона слишком короткий")
        return
    }

    currentUser = phone

    document.getElementById("loginScreen").style.display = "none"
    document.getElementById("app").style.display = "flex"
    document.getElementById("sidebar").classList.add('open')

    document.getElementById("myPhone").innerText = formatPhone(phone)

    // Загружаем профиль пользователя
    loadUserProfile()
    connect()
    loadChats()
}

// Загрузка профиля текущего пользователя
async function loadUserProfile() {
    try {
        const res = await fetch(`/user/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load profile')
        const data = await res.json()

        currentUserProfile = data

        // Отображаем профиль
        const displayName = data.name || data.username || data.phone
        document.getElementById("myDisplayName").innerText = displayName
        document.getElementById("myAvatarText").innerText = getAvatarLetter(displayName)

    } catch (error) {
        console.error("Error loading profile:", error)
    }
}

// Открыть свой профиль
function openMyProfile() {
    showUserProfile(currentUser, true)
}

// Открыть профиль чата
function openChatProfile() {
    if (currentChat) {
        showUserProfile(currentChat, false)
    }
}

// Показать профиль пользователя
async function showUserProfile(phone, isMyProfile = false) {
    try {
        const res = await fetch(`/user/${phone}`)
        if (!res.ok) throw new Error('Failed to load user')
        const user = await res.json()

        const modal = document.getElementById('profileModal')
        const profileView = document.querySelector('.profile-view')
        const profileEdit = document.getElementById('profileEdit')
        const modalActions = document.getElementById('modalActions')

        // Заполняем данные
        const displayName = user.name || user.username || user.phone
        document.getElementById('modalAvatarText').innerText = getAvatarLetter(displayName)
        document.getElementById('modalName').innerText = user.name || 'Не указано'
        document.getElementById('modalUsername').innerText = user.username || 'Не установлен'
        document.getElementById('modalPhone').innerText = formatPhone(user.phone)

        // Статус онлайн/оффлайн
        const isOnline = window.clients ? window.clients[phone] : false
        document.getElementById('modalStatus').innerHTML = isOnline ?
            '<span style="color: #4ade80;">● Онлайн</span>' :
            '<span style="color: #f87171;">● Оффлайн</span>'

        // Действия в зависимости от того, свой профиль или чужой
        modalActions.innerHTML = ''

        if (isMyProfile) {
            // Свой профиль - кнопка редактирования
            profileView.style.display = 'block'
            profileEdit.style.display = 'none'

            const editBtn = document.createElement('button')
            editBtn.className = 'action-button primary'
            editBtn.innerText = 'Редактировать профиль'
            editBtn.onclick = () => {
                document.getElementById('editName').value = user.name || ''
                document.getElementById('editUsername').value = user.username || ''
                profileView.style.display = 'none'
                profileEdit.style.display = 'block'
            }
            modalActions.appendChild(editBtn)

        } else {
            // Чужой профиль - кнопка "Написать"
            profileView.style.display = 'block'
            profileEdit.style.display = 'none'

            const messageBtn = document.createElement('button')
            messageBtn.className = 'action-button primary'
            messageBtn.innerText = 'Написать сообщение'
            messageBtn.onclick = () => {
                closeModal()
                openChat(phone, displayName)
            }
            modalActions.appendChild(messageBtn)
        }

        modal.classList.add('show')

    } catch (error) {
        console.error("Error loading user profile:", error)
        showToast("Ошибка загрузки профиля")
    }
}

// Сохранить профиль
async function saveProfile() {
    const username = document.getElementById('editUsername').value.trim()
    const name = document.getElementById('editName').value.trim()

    if (!username) {
        showToast("Введите username")
        return
    }

    if (!username.startsWith('@')) {
        showToast("Username должен начинаться с @")
        return
    }

    try {
        const res = await fetch('/username', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: currentUser,
                username: username,
                name: name || username.substring(1) // Если имя не указано, используем username без @
            })
        })

        const data = await res.json()

        if (data.error) {
            showToast(data.error)
            return
        }

        showToast('Профиль обновлен')
        closeModal()

        // Обновляем отображение
        await loadUserProfile()
        loadChats()

    } catch (error) {
        console.error("Error saving profile:", error)
        showToast("Ошибка сохранения")
    }
}

// Отмена редактирования
function cancelEdit() {
    document.querySelector('.profile-view').style.display = 'block'
    document.getElementById('profileEdit').style.display = 'none'
}

// Закрыть модальное окно
function closeModal() {
    document.getElementById('profileModal').classList.remove('show')
}

// Подключение WebSocket
function connect() {
    // Очищаем предыдущие интервалы
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)

    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/ws/${currentUser}`

        console.log('Connecting to:', wsUrl)
        ws = new WebSocket(wsUrl)

        ws.onopen = () => {
            console.log('WebSocket connected')
            isConnected = true
            reconnectAttempts = 0
            showToast('Подключено к серверу')

            // Пинг каждые 30 секунд
            pingInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'ping' }))
                }
            }, 30000)
        }

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)

                // Игнорируем pong
                if (data.action === 'pong') return

                if (data.action === "message") {
                    addMessage(data.from, data.text)
                    loadChats()

                    if (currentChat !== data.from) {
                        showToast(`Новое сообщение`)
                        if (window.navigator.vibrate) {
                            window.navigator.vibrate(200)
                        }
                    }
                }

                if (data.action === "history") {
                    document.getElementById("messages").innerHTML = ""
                    data.messages.forEach(m => {
                        addMessage(m[0], m[1])
                    })
                }

                if (data.action === "typing") {
                    if (currentChat === data.from) {
                        document.getElementById('chatUserStatus').textContent = 'печатает...'
                        clearTimeout(window.typingStatusTimeout)
                        window.typingStatusTimeout = setTimeout(() => {
                            if (currentChat === data.from) {
                                document.getElementById('chatUserStatus').textContent = 'online'
                            }
                        }, 3000)
                    }
                }
            } catch (error) {
                console.error('Error parsing message:', error)
            }
        }

        ws.onclose = (event) => {
            console.log('WebSocket disconnected:', event.code, event.reason)
            isConnected = false
            if (pingInterval) clearInterval(pingInterval)

            if (event.code !== 1000) {
                handleReconnect()
            }
        }

        ws.onerror = (error) => {
            console.error('WebSocket error:', error)
            isConnected = false
        }

    } catch (error) {
        console.error('Connection error:', error)
        handleReconnect()
    }
}

// Обработка переподключения
function handleReconnect() {
    if (reconnectAttempts < maxReconnectAttempts && currentUser) {
        reconnectAttempts++
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000)

        reconnectTimeout = setTimeout(() => {
            if (!isConnected && currentUser) {
                connect()
            }
        }, delay)
    }
}

// Загрузка списка чатов
async function loadChats() {
    if (!currentUser) return

    try {
        let res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')

        let chats = await res.json()

        let list = document.getElementById("chatList")
        list.innerHTML = ""

        document.getElementById('chatsCount').textContent = chats.length

        for (let chat of chats) {
            // Загружаем профиль собеседника
            const userRes = await fetch(`/user/${chat.phone}`)
            const userData = await userRes.json()

            let div = document.createElement("div")
            div.className = "chatItem"
            if (chat.phone === currentChat) {
                div.classList.add('active')
            }

            const displayName = userData.name || userData.username || chat.phone
            const lastMessage = chat.last || 'Нет сообщений'

            div.innerHTML = `
                <div class="chat-avatar">${escapeHtml(getAvatarLetter(displayName))}</div>
                <div class="chat-info">
                    <div class="chat-name">${escapeHtml(displayName)}</div>
                    <div class="chat-last-message">${escapeHtml(lastMessage)}</div>
                </div>
                <div class="chat-status ${chat.online ? '' : 'offline'}"></div>
            `

            div.onclick = () => openChat(chat.phone, displayName)
            list.appendChild(div)
        }

    } catch (error) {
        console.error("Error loading chats:", error)
        showToast("Ошибка загрузки чатов")
    }
}

// Открыть чат
function openChat(phone, displayName) {
    currentChat = phone

    // Загружаем профиль для отображения в шапке
    fetch(`/user/${phone}`)
        .then(res => res.json())
        .then(user => {
            const name = user.name || user.username || phone
            document.getElementById("chatUserName").innerText = name
            document.getElementById("chatUserPhone").innerText = formatPhone(phone)
            document.getElementById("chatAvatarText").innerText = getAvatarLetter(name)
        })
        .catch(() => {
            document.getElementById("chatUserName").innerText = displayName || phone
            document.getElementById("chatUserPhone").innerText = formatPhone(phone)
            document.getElementById("chatAvatarText").innerText = getAvatarLetter(displayName || phone)
        })

    document.getElementById("emptyChat").style.display = "none"
    document.getElementById("chatBlock").style.display = "flex"

    if (window.innerWidth <= 768) {
        document.getElementById("sidebar").classList.remove('open')
    }

    loadMessages()
}

// Загрузка истории сообщений
function loadMessages() {
    if (!currentChat || !ws || ws.readyState !== WebSocket.OPEN) {
        showToast("Нет соединения с сервером")
        return
    }

    ws.send(JSON.stringify({
        action: "history",
        user: currentChat
    }))
}

// Отправка сообщения
function send() {
    if (!currentChat) {
        showToast("Выберите чат")
        return
    }

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        showToast("Нет соединения с сервером")
        return
    }

    const text = document.getElementById("text").value.trim()

    if (!text) return

    ws.send(JSON.stringify({
        action: "send",
        to: currentChat,
        text: text
    }))

    addMessage(currentUser, text)
    document.getElementById("text").value = ""
}

// Добавление сообщения в окно чата
function addMessage(user, text) {
    const messagesDiv = document.getElementById("messages")
    const div = document.createElement("div")

    div.className = "message " + (user === currentUser ? "me" : "other")

    const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })

    div.innerHTML = `
        <div class="message-text">${escapeHtml(text)}</div>
        <div class="message-time">${time}</div>
    `

    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

// Индикатор печатания
document.getElementById("text").addEventListener("input", () => {
    if (!currentChat || !ws || ws.readyState !== WebSocket.OPEN) return

    clearTimeout(typingTimeout)

    ws.send(JSON.stringify({
        action: "typing",
        to: currentChat,
        typing: true
    }))

    typingTimeout = setTimeout(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                action: "typing",
                to: currentChat,
                typing: false
            }))
        }
    }, 2000)
})

// Поиск пользователей
async function search() {
    const username = document.getElementById("searchUser").value.trim()

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

        if (!res.ok) throw new Error('Search failed')
        const data = await res.json()

        if (!data.found) {
            showToast("Пользователь не найден")
            return
        }

        // Показываем профиль найденного пользователя
        showUserProfile(data.phone, false)
        document.getElementById("searchUser").value = ""

    } catch (error) {
        console.error("Search error:", error)
        showToast("Ошибка при поиске")
    }
}

// Обработка Enter для отправки
document.getElementById("text").addEventListener("keypress", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault()
        send()
    }
})

// Закрытие модального окна по Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal()
    }
})

// Закрытие модального окна по клику вне его
window.onclick = function(event) {
    const modal = document.getElementById('profileModal')
    if (event.target === modal) {
        closeModal()
    }
}

// Обработка потери соединения
window.addEventListener('online', () => {
    showToast('Соединение восстановлено')
    if (!isConnected && currentUser) {
        connect()
    }
})

window.addEventListener('offline', () => {
    showToast('Потеряно соединение с интернетом')
})

// Адаптация при изменении размера окна
window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        document.getElementById('sidebar').classList.remove('open')
    }
})

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPhone').focus()
})

// Очистка при закрытии страницы
window.addEventListener('beforeunload', () => {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)
    if (ws) ws.close(1000, 'Page closed')
})