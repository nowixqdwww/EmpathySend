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
let selectedMessageId = null
let selectedMessageElement = null

// Глобальный объект для хранения онлайн статусов
window.clients = {}

// Хранилище чатов и непрочитанных сообщений
let chatsCache = {}
let unreadCounts = {}

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
    if (phone.length === 11) {
        return phone.replace(/(\d{1})(\d{3})(\d{3})(\d{2})(\d{2})/, '+$1 ($2) $3-$4-$5')
    }
    return phone
}

// Получение первой буквы для аватара
function getAvatarLetter(name) {
    if (!name) return '👤'
    if (name.startsWith('@') && name.length > 1) {
        return name[1].toUpperCase()
    }
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
        
        const displayName = data.name || data.username || data.phone
        document.getElementById("myDisplayName").innerText = displayName
        
        const myAvatar = document.getElementById("myAvatarText")
        if (data.avatar) {
            myAvatar.innerHTML = `<img src="${data.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
        } else {
            myAvatar.innerText = getAvatarLetter(displayName)
        }
        
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
        const profileView = document.getElementById('profileView')
        const profileEdit = document.getElementById('profileEdit')
        const modalActions = document.getElementById('modalActions')
        
        const displayName = user.name || user.username || user.phone
        
        const modalAvatar = document.getElementById('modalAvatarText')
        if (user.avatar) {
            modalAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
        } else {
            modalAvatar.innerText = getAvatarLetter(displayName)
        }
        
        document.getElementById('modalName').innerText = user.name || 'Не указано'
        document.getElementById('modalUsername').innerText = user.username || 'Не установлен'
        document.getElementById('modalBio').innerText = user.bio || 'Не указано' // НОВОЕ
        document.getElementById('modalPhone').innerText = formatPhone(user.phone)
        
        let isOnline = false
        if (window.clients && typeof window.clients === 'object') {
            isOnline = phone in window.clients
        }
        
        document.getElementById('modalStatus').innerHTML = isOnline ? 
            '<span style="color: #4ade80;">● Онлайн</span>' : 
            '<span style="color: #f87171;">● Оффлайн</span>'
        
        modalActions.innerHTML = ''
        
        if (isMyProfile) {
            profileView.style.display = 'block'
            profileEdit.style.display = 'none'
            
            const editBtn = document.createElement('button')
            editBtn.className = 'action-button primary'
            editBtn.innerText = 'Редактировать профиль'
            editBtn.onclick = () => {
                document.getElementById('editName').value = user.name || ''
                document.getElementById('editUsername').value = user.username || ''
                document.getElementById('editBio').value = user.bio || '' // НОВОЕ
                
                const previewAvatar = document.getElementById('previewAvatarText')
                if (user.avatar) {
                    previewAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
                } else {
                    previewAvatar.innerText = getAvatarLetter(displayName)
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

// Предпросмотр аватара
document.getElementById('avatarInput')?.addEventListener('change', function(e) {
    const file = e.target.files[0]
    if (file) {
        const reader = new FileReader()
        reader.onload = function(e) {
            document.getElementById('previewAvatarText').innerHTML = 
                `<img src="${e.target.result}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
        }
        reader.readAsDataURL(file)
    }
})

// Загрузка аватара
async function uploadAvatar() {
    const input = document.getElementById('avatarInput')
    const file = input.files[0]
    
    if (!file) {
        showToast("Выберите файл")
        return
    }
    
    if (file.size > 2 * 1024 * 1024) {
        showToast("Файл слишком большой (макс 2MB)")
        return
    }
    
    const formData = new FormData()
    formData.append('file', file)
    
    try {
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
        
        await loadUserProfile()
        loadChats()
        closeModal()
        
    } catch (error) {
        console.error("Error uploading avatar:", error)
        showToast("Ошибка загрузки")
    }
}

// Удаление аватара
async function removeAvatar() {
    if (!confirm('Удалить аватар?')) return
    
    try {
        const res = await fetch(`/remove-avatar/${currentUser}`, {
            method: 'POST'
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        showToast('Аватар удален')
        
        document.getElementById('previewAvatarText').innerText = '👤'
        document.getElementById('avatarInput').value = ''
        
        await loadUserProfile()
        loadChats()
        
    } catch (error) {
        console.error("Error removing avatar:", error)
        showToast("Ошибка удаления")
    }
}

// Сохранить профиль
async function saveProfile() {
    const username = document.getElementById('editUsername').value.trim()
    const name = document.getElementById('editName').value.trim()
    const bio = document.getElementById('editBio').value.trim() // НОВОЕ
    
    if (!username) {
        showToast("Введите username")
        return
    }
    
    if (!username.startsWith('@')) {
        showToast("Username должен начинаться с @")
        return
    }
    
    const avatarInput = document.getElementById('avatarInput')
    if (avatarInput.files.length > 0) {
        await uploadAvatar()
    }
    
    try {
        const res = await fetch('/username', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: currentUser,
                username: username,
                name: name || username.substring(1),
                bio: bio // НОВОЕ
            })
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
        console.error("Error saving profile:", error)
        showToast("Ошибка сохранения")
    }
}

// Отмена редактирования
function cancelEdit() {
    document.getElementById('profileView').style.display = 'block'
    document.getElementById('profileEdit').style.display = 'none'
}

// Закрыть модальное окно
function closeModal() {
    document.getElementById('profileModal').classList.remove('show')
}

// Подключение WebSocket
function connect() {
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
            
            updateOnlineStatus()
            
            pingInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'ping' }))
                }
            }, 30000)
        }

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)

                if (data.action === 'pong') return

                if (data.action === "message_sent") {
                    // Сообщение отправлено, создаем/обновляем чат
                    updateSingleChat(data.to, true)
                }

                if (data.action === "message") {
                    addMessage(data.from, data.text, data.id)
                    
                    // Проверяем, есть ли уже чат
                    const existingChat = document.getElementById(`chat-${data.from}`)
                    
                    if (!existingChat) {
                        // Если чата нет - создаем новый
                        updateSingleChat(data.from, true)
                    } else {
                        // Если чат есть - поднимаем наверх и обновляем последнее сообщение
                        const list = document.getElementById("chatList")
                        list.prepend(existingChat)
                        
                        // Обновляем последнее сообщение
                        const lastMsgElement = existingChat.querySelector('.chat-last-message')
                        if (lastMsgElement) {
                            lastMsgElement.innerText = data.text
                        }
                    }
                    
                    if (currentChat !== data.from) {
                        unreadCounts[data.from] = (unreadCounts[data.from] || 0) + 1
                        
                        // Обновляем счетчик
                        const badge = existingChat?.querySelector('.unread-badge')
                        if (badge) {
                            badge.textContent = unreadCounts[data.from] > 99 ? '99+' : unreadCounts[data.from]
                        } else if (existingChat) {
                            const newBadge = document.createElement('span')
                            newBadge.className = 'unread-badge'
                            newBadge.textContent = unreadCounts[data.from] > 99 ? '99+' : unreadCounts[data.from]
                            existingChat.appendChild(newBadge)
                        }
                        
                        showToast(`Новое сообщение`)
                        if (window.navigator.vibrate) {
                            window.navigator.vibrate(200)
                        }
                    }
                }

                if (data.action === "message_deleted") {
                    const messageElement = document.querySelector(`[data-message-id="${data.message_id}"]`)
                    if (messageElement) {
                        messageElement.remove()
                    }
                }

                if (data.action === "history") {
                    document.getElementById("messages").innerHTML = ""
                    data.messages.forEach(m => {
                        addMessage(m[1], m[2], m[0])
                    })
                    
                    if (currentChat) {
                        unreadCounts[currentChat] = 0
                        updateSingleChat(currentChat)
                    }
                }

                if (data.action === "typing") {
                    if (currentChat === data.from) {
                        document.getElementById('chatUserStatus').textContent = 'печатает...'
                        clearTimeout(window.typingStatusTimeout)
                        window.typingStatusTimeout = setTimeout(() => {
                            if (currentChat === data.from) {
                                let isOnline = window.clients && data.from in window.clients
                                document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
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

// Обновление онлайн статусов
function updateOnlineStatus() {
    document.querySelectorAll('.chatItem').forEach(item => {
        const phone = item.id.replace('chat-', '')
        const statusDot = item.querySelector('.chat-status')
        if (statusDot) {
            const isOnline = window.clients && phone in window.clients
            statusDot.className = `chat-status ${isOnline ? '' : 'offline'}`
        }
    })
    
    if (currentChat) {
        const isOnline = window.clients && currentChat in window.clients
        document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
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
        
        // Обновляем кэш
        chats.forEach(chat => {
            chatsCache[chat.phone] = chat
        })
        
        // Сортируем по последнему сообщению (самые новые сверху)
        chats.sort((a, b) => {
            if (!a.last) return 1
            if (!b.last) return -1
            return 0
        })
        
        renderChatList(chats)

    } catch (error) {
        console.error("Error loading chats:", error)
        showToast("Ошибка загрузки чатов")
    }
}

// Отрисовка списка чатов
function renderChatList(chats) {
    let list = document.getElementById("chatList")
    list.innerHTML = ""

    document.getElementById('chatsCount').textContent = chats.length

    chats.forEach(chat => {
        const chatElement = createChatElement(chat)
        list.appendChild(chatElement)
    })
}

// Создание элемента чата
function createChatElement(chat) {
    const displayName = chat.displayName || chat.name || chat.username || chat.phone
    const lastMessage = chat.last || 'Нет сообщений'
    const unreadCount = unreadCounts[chat.phone] || 0
    
    let div = document.createElement("div")
    div.className = "chatItem"
    div.id = `chat-${chat.phone}`
    
    if (chat.phone === currentChat) {
        div.classList.add('active')
    }
    
    let avatarHtml
    if (chat.avatar) {
        avatarHtml = `<img src="${chat.avatar}" class="chat-avatar-img" alt="avatar">`
    } else {
        avatarHtml = escapeHtml(getAvatarLetter(displayName))
    }
    
    const isOnline = window.clients && chat.phone in window.clients
    
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
    
    div.onclick = () => openChat(chat.phone, displayName)
    return div
}

// Обновление одного чата и поднятие наверх
async function updateSingleChat(phone, moveToTop = false) {
    try {
        // Проверяем, есть ли уже такой элемент
        const existingElement = document.getElementById(`chat-${phone}`)
        if (existingElement && !moveToTop) {
            return // Если элемент уже есть и не нужно поднимать - выходим
        }
        
        // Загружаем свежие данные
        const res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')
        
        const chats = await res.json()
        const updatedChat = chats.find(c => c.phone === phone)
        
        if (!updatedChat) {
            // Если чата нет в списке, но мы его хотим создать
            const userRes = await fetch(`/user/${phone}`)
            const userData = await userRes.json()
            
            const newChat = {
                phone: phone,
                username: userData.username,
                name: userData.name,
                displayName: userData.name || userData.username || phone,
                avatar: userData.avatar,
                online: phone in window.clients,
                last: ''
            }
            
            chatsCache[phone] = newChat
            
            const list = document.getElementById("chatList")
            const newChatElement = createChatElement(newChat)
            
            if (moveToTop) {
                list.prepend(newChatElement)
            } else {
                list.appendChild(newChatElement)
            }
            
            const count = document.getElementById("chatsCount")
            count.textContent = parseInt(count.textContent) + 1
            
            return
        }
        
        // Обновляем существующий чат
        updatedChat.unread = unreadCounts[phone] || 0
        chatsCache[phone] = updatedChat
        
        const list = document.getElementById("chatList")
        let chatElement = document.getElementById(`chat-${phone}`)
        
        if (chatElement) {
            // Обновляем существующий элемент
            const displayName = updatedChat.displayName || updatedChat.name || updatedChat.username || phone
            const lastMessage = updatedChat.last || 'Нет сообщений'
            const unreadCount = unreadCounts[phone] || 0
            
            const nameElement = chatElement.querySelector('.chat-name')
            const lastMessageElement = chatElement.querySelector('.chat-last-message')
            const avatarElement = chatElement.querySelector('.chat-avatar')
            const statusDot = chatElement.querySelector('.chat-status')
            
            if (nameElement) nameElement.innerText = displayName
            if (lastMessageElement) lastMessageElement.innerText = lastMessage
            
            if (updatedChat.avatar) {
                avatarElement.innerHTML = `<img src="${updatedChat.avatar}" class="chat-avatar-img" alt="avatar">`
            } else {
                avatarElement.innerText = getAvatarLetter(displayName)
            }
            
            const isOnline = window.clients && phone in window.clients
            if (statusDot) {
                statusDot.className = `chat-status ${isOnline ? '' : 'offline'}`
            }
            
            let badge = chatElement.querySelector('.unread-badge')
            if (unreadCount > 0) {
                if (!badge) {
                    badge = document.createElement('span')
                    badge.className = 'unread-badge'
                    chatElement.appendChild(badge)
                }
                badge.textContent = unreadCount > 99 ? '99+' : unreadCount
            } else if (badge) {
                badge.remove()
            }
            
            if (moveToTop) {
                list.prepend(chatElement)
            }
            
        } else {
            // Создаем новый элемент
            const newChat = createChatElement(updatedChat)
            if (moveToTop) {
                list.prepend(newChat)
            } else {
                list.appendChild(newChat)
            }
            
            const count = document.getElementById("chatsCount")
            count.textContent = parseInt(count.textContent) + 1
        }
        
    } catch (error) {
        console.error("Error updating single chat:", error)
    }
}

// Открыть чат
function openChat(phone, displayName) {
    // Если уже открыт этот чат - не делаем ничего
    if (currentChat === phone) {
        return
    }
    
    currentChat = phone
    
    unreadCounts[phone] = 0
    
    // Обновляем отображение чата (убираем бейдж)
    updateSingleChat(phone, false)
    
    // Загружаем профиль для отображения в шапке
    fetch(`/user/${phone}`)
        .then(res => res.json())
        .then(user => {
            const name = user.name || user.username || phone
            document.getElementById("chatUserName").innerText = name
            document.getElementById("chatUserPhone").innerText = formatPhone(phone)
            
            const chatAvatar = document.getElementById("chatAvatarText")
            if (user.avatar) {
                chatAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`
            } else {
                chatAvatar.innerText = getAvatarLetter(name)
            }
            
            const isOnline = window.clients && phone in window.clients
            document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
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
    
    // Убираем активный класс у всех чатов
    document.querySelectorAll('.chatItem').forEach(el => {
        el.classList.remove('active')
    })
    
    // Добавляем активный класс текущему чату
    const activeChat = document.getElementById(`chat-${phone}`)
    if (activeChat) {
        activeChat.classList.add('active')
    }
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

    // Отправляем сообщение
    ws.send(JSON.stringify({
        action: "send",
        to: currentChat,
        text: text
    }))

    // Добавляем сообщение в интерфейс
    addMessage(currentUser, text)
    document.getElementById("text").value = ""
    
    // Обновляем чат (поднимаем наверх) ТОЛЬКО если это новый чат
    // Проверяем, есть ли уже этот чат в списке
    const existingChat = document.getElementById(`chat-${currentChat}`)
    if (!existingChat) {
        // Если чата нет - создаем
        updateSingleChat(currentChat, true)
    } else {
        // Если чат есть - просто поднимаем наверх
        const list = document.getElementById("chatList")
        list.prepend(existingChat)
    }
}

// Добавление сообщения в окно чата
function addMessage(user, text, messageId = null) {
    const messagesDiv = document.getElementById("messages")
    const div = document.createElement("div")
    
    div.className = "message " + (user === currentUser ? "me" : "other")
    
    if (messageId) {
        div.dataset.messageId = messageId
    }
    
    const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    
    div.innerHTML = `
        <div class="message-text">${escapeHtml(text)}</div>
        <div class="message-time">${time}</div>
    `
    
    if (user === currentUser && messageId) {
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault()
            openMessageContext(e, messageId, div)
        })
        
        // Для мобильных - долгое нажатие
        let pressTimer
        div.addEventListener('touchstart', (e) => {
            pressTimer = setTimeout(() => {
                openMessageContext(e, messageId, div)
            }, 500)
        })
        div.addEventListener('touchend', () => {
            clearTimeout(pressTimer)
        })
        div.addEventListener('touchmove', () => {
            clearTimeout(pressTimer)
        })
    }
    
    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

// Открыть контекстное меню для сообщения
function openMessageContext(event, messageId, messageElement) {
    event.preventDefault()
    event.stopPropagation()
    
    selectedMessageId = messageId
    selectedMessageElement = messageElement
    
    const menu = document.getElementById('messageContextMenu')
    menu.style.display = 'block'
    menu.style.left = (event.pageX || event.touches[0].pageX) + 'px'
    menu.style.top = (event.pageY || event.touches[0].pageY) + 'px'
}

// Закрыть контекстное меню
document.addEventListener('click', () => {
    document.getElementById('messageContextMenu').style.display = 'none'
})

document.addEventListener('touchstart', () => {
    document.getElementById('messageContextMenu').style.display = 'none'
})

// Удалить сообщение
async function deleteMessage() {
    if (!selectedMessageId || !currentChat) return
    
    try {
        const res = await fetch('/delete-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message_id: selectedMessageId,
                user: currentUser
            })
        })
        
        const data = await res.json()
        
        if (data.error) {
            showToast(data.error)
            return
        }
        
        if (selectedMessageElement) {
            selectedMessageElement.remove()
        }
        
        showToast('Сообщение удалено')
        
    } catch (error) {
        console.error("Error deleting message:", error)
        showToast("Ошибка при удалении")
    }
    
    document.getElementById('messageContextMenu').style.display = 'none'
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

        showUserProfile(data.phone, false)
        document.getElementById("searchUser").value = ""

    } catch (error) {
        console.error("Search error:", error)
        showToast("Ошибка при поиске")
    }
}

// Обработка Enter
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

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPhone').focus()
})

// Очистка при закрытии
window.addEventListener('beforeunload', () => {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)
    if (ws) ws.close(1000, 'Page closed')
})

// Периодическое обновление онлайн статусов
setInterval(updateOnlineStatus, 5000)



