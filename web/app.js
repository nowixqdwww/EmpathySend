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
let selectedChatPhone = null
let selectedChatElement = null

// Для долгого нажатия
let longPressTimer = null
let longPressTarget = null

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

// Очистка номера от пробелов
function cleanPhone(phone) {
    return phone.replace(/\s+/g, '').trim()
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
        
        console.log('Profile data:', data)
        
        currentUserProfile = data
        
        const displayName = data.name || data.username || data.phone
        document.getElementById("myDisplayName").innerText = displayName
        
        const myAvatar = document.getElementById("myAvatarText")
        if (data.avatar) {
            myAvatar.innerHTML = `<img src="${data.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
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
            modalAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
        } else {
            modalAvatar.innerText = getAvatarLetter(displayName)
        }
        
        document.getElementById('modalName').innerText = user.name || 'Не указано'
        document.getElementById('modalUsername').innerText = user.username || 'Не установлен'
        document.getElementById('modalBio').innerText = user.bio || 'Не указано'
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
                document.getElementById('editBio').value = user.bio || ''
                
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
    const bio = document.getElementById('editBio').value.trim()
    
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
                bio: bio
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

// Функция для показа контекстного меню
function showContextMenu(event, type, data) {
    event.preventDefault()
    event.stopPropagation()
    
    // Закрываем все открытые меню
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    
    let menu
    let menuId
    
    if (type === 'message') {
        menuId = 'messageContextMenu'
        selectedMessageId = data.messageId
        selectedMessageElement = data.element
    } else if (type === 'chat') {
        menuId = 'chatContextMenu'
        selectedChatPhone = data.phone
        selectedChatElement = data.element
    }
    
    menu = document.getElementById(menuId)
    
    // Получаем координаты
    let x, y
    
    if (event.touches) {
        // Мобильное устройство
        x = event.touches[0].pageX
        y = event.touches[0].pageY
        event.preventDefault()
    } else {
        // ПК
        x = event.pageX
        y = event.pageY
    }
    
    // Позиционируем меню
    menu.style.display = 'block'
    menu.style.left = x + 'px'
    menu.style.top = y + 'px'
    
    // Проверяем границы экрана
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

// Обработчик долгого нажатия
function handleLongPress(event, type, data) {
    event.preventDefault()
    event.stopPropagation()
    
    if (longPressTimer) {
        clearTimeout(longPressTimer)
    }
    
    longPressTarget = { type, data, event }
    
    longPressTimer = setTimeout(() => {
        if (longPressTarget) {
            if (window.navigator.vibrate) {
                window.navigator.vibrate(50)
            }
            showContextMenu(
                longPressTarget.event,
                longPressTarget.type,
                longPressTarget.data
            )
            longPressTarget = null
        }
    }, 500)
}

// Обработчик окончания касания
function handleTouchEnd() {
    if (longPressTimer) {
        clearTimeout(longPressTimer)
        longPressTimer = null
    }
    longPressTarget = null
}

// Обработчик движения пальца
function handleTouchMove() {
    if (longPressTimer) {
        clearTimeout(longPressTimer)
        longPressTimer = null
    }
    longPressTarget = null
}

// Скрыть все контекстные меню
function hideContextMenus() {
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    selectedMessageId = null
    selectedMessageElement = null
    selectedChatPhone = null
    selectedChatElement = null
}

// Закрытие меню при клике вне
document.addEventListener('click', hideContextMenus)
document.addEventListener('touchstart', hideContextMenus)

// Предотвращаем стандартное контекстное меню
document.addEventListener('contextmenu', (e) => {
    if (e.target.closest('.message') || e.target.closest('.chatItem')) {
        e.preventDefault()
    }
})

// Предотвращаем выделение на мобильных
document.addEventListener('selectstart', (e) => {
    if (e.target.closest('.message') || e.target.closest('.chatItem')) {
        e.preventDefault()
    }
})

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

                if (data.action === "message") {
                    addMessage(data.from, data.text, data.id)
                    
                    const cleanFrom = cleanPhone(data.from)
                    const existingChat = document.getElementById(`chat-${cleanFrom}`)
                    
                    if (!existingChat) {
                        updateSingleChat(data.from, true)
                    } else {
                        const list = document.getElementById("chatList")
                        list.prepend(existingChat)
                        
                        const lastMsgElement = existingChat.querySelector('.chat-last-message')
                        if (lastMsgElement) {
                            lastMsgElement.innerText = data.text
                        }
                    }
                    
                    if (currentChat !== data.from) {
                        unreadCounts[data.from] = (unreadCounts[data.from] || 0) + 1
                        
                        const chatElement = document.getElementById(`chat-${cleanFrom}`)
                        const badge = chatElement?.querySelector('.unread-badge')
                        if (badge) {
                            badge.textContent = unreadCounts[data.from] > 99 ? '99+' : unreadCounts[data.from]
                        } else if (chatElement) {
                            const newBadge = document.createElement('span')
                            newBadge.className = 'unread-badge'
                            newBadge.textContent = unreadCounts[data.from] > 99 ? '99+' : unreadCounts[data.from]
                            chatElement.appendChild(newBadge)
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

                if (data.action === "message_sent") {
                    updateSingleChat(data.to, true)
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

// Очистка дубликатов чатов
function removeDuplicateChats() {
    const chatList = document.getElementById("chatList")
    const seen = new Set()
    const duplicates = []
    
    const chats = chatList.querySelectorAll('.chatItem')
    
    chats.forEach(chat => {
        const id = chat.id
        if (seen.has(id)) {
            duplicates.push(chat)
        } else {
            seen.add(id)
        }
    })
    
    duplicates.forEach(dup => dup.remove())
    
    if (duplicates.length > 0) {
        console.log(`Removed ${duplicates.length} duplicate chats`)
    }
}

// Загрузка списка чатов
async function loadChats() {
    if (!currentUser) return
    
    try {
        let res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')
        
        let chats = await res.json()
        
        chats.forEach(chat => {
            chatsCache[chat.phone] = chat
        })
        
        chats.sort((a, b) => {
            if (!a.last) return 1
            if (!b.last) return -1
            return 0
        })
        
        renderChatList(chats)
        
        // Очищаем дубликаты после рендера
        setTimeout(removeDuplicateChats, 100)
        
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
    const cleanPhone = cleanPhone(chat.phone)
    div.id = `chat-${cleanPhone}`
    
    if (chat.phone === currentChat) {
        div.classList.add('active')
    }
    
    let avatarHtml
    if (chat.avatar) {
        avatarHtml = `<img src="${chat.avatar}" class="chat-avatar-img" alt="avatar" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
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
    
    // Обработчики для ПК
    div.addEventListener('contextmenu', (e) => {
        e.preventDefault()
        showContextMenu(e, 'chat', { phone: chat.phone, element: div })
    })
    
    // Обработчики для мобильных
    div.addEventListener('touchstart', (e) => {
        handleLongPress(e, 'chat', { phone: chat.phone, element: div })
    })
    
    div.addEventListener('touchend', handleTouchEnd)
    div.addEventListener('touchmove', handleTouchMove)
    div.addEventListener('touchcancel', handleTouchEnd)
    
    div.onclick = () => openChat(chat.phone, displayName)
    return div
}

// Обновление одного чата
async function updateSingleChat(phone, moveToTop = false) {
    try {
        const cleanPhone = cleanPhone(phone)
        
        const existingElement = document.getElementById(`chat-${cleanPhone}`)
        if (existingElement && !moveToTop) {
            return
        }
        
        const res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')
        
        const chats = await res.json()
        const updatedChat = chats.find(c => c.phone === phone || cleanPhone(c.phone) === cleanPhone)
        
        if (!updatedChat) {
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
        
        updatedChat.unread = unreadCounts[phone] || 0
        chatsCache[phone] = updatedChat
        
        const list = document.getElementById("chatList")
        let chatElement = document.getElementById(`chat-${cleanPhone}`)
        
        if (chatElement) {
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
                avatarElement.innerHTML = `<img src="${updatedChat.avatar}" class="chat-avatar-img" alt="avatar" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
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
            const newChat = createChatElement(updatedChat)
            if (moveToTop) {
                list.prepend(newChat)
            } else {
                list.appendChild(newChat)
            }
            
            const count = document.getElementById("chatsCount")
            count.textContent = parseInt(count.textContent) + 1
        }
        
        // Очищаем дубликаты
        setTimeout(removeDuplicateChats, 50)
        
    } catch (error) {
        console.error("Error updating single chat:", error)
    }
}

// Открыть чат
function openChat(phone, displayName) {
    if (currentChat === phone) return
    
    currentChat = phone
    unreadCounts[phone] = 0
    
    updateSingleChat(phone, false)
    
    fetch(`/user/${phone}`)
        .then(res => res.json())
        .then(user => {
            const name = user.name || user.username || phone
            document.getElementById("chatUserName").innerText = name
            document.getElementById("chatUserPhone").innerText = formatPhone(phone)
            
            const chatAvatar = document.getElementById("chatAvatarText")
            if (user.avatar) {
                chatAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${name}')">`
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
    
    document.querySelectorAll('.chatItem').forEach(el => {
        el.classList.remove('active')
    })
    
    const cleanPhone = cleanPhone(phone)
    const activeChat = document.getElementById(`chat-${cleanPhone}`)
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

    ws.send(JSON.stringify({
        action: "send",
        to: currentChat,
        text: text
    }))

    addMessage(currentUser, text)
    document.getElementById("text").value = ""
    
    const cleanPhone = cleanPhone(currentChat)
    const existingChat = document.getElementById(`chat-${cleanPhone}`)
    if (!existingChat) {
        updateSingleChat(currentChat, true)
    } else {
        const list = document.getElementById("chatList")
        list.prepend(existingChat)
    }
}

// Добавление сообщения
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
        // Обработчики для ПК
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault()
            showContextMenu(e, 'message', { messageId: messageId, element: div })
        })
        
        // Обработчики для мобильных
        div.addEventListener('touchstart', (e) => {
            handleLongPress(e, 'message', { messageId: messageId, element: div })
        })
        
        div.addEventListener('touchend', handleTouchEnd)
        div.addEventListener('touchmove', handleTouchMove)
        div.addEventListener('touchcancel', handleTouchEnd)
    }
    
    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

// Удаление сообщения
async function deleteMessage() {
    if (!selectedMessageId || !currentChat) {
        hideContextMenus()
        return
    }
    
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
    
    hideContextMenus()
}

// Удаление чата
async function deleteChat() {
    if (!selectedChatPhone) {
        hideContextMenus()
        return
    }
    
    if (!confirm('Удалить этот чат? Вся история сообщений будет удалена.')) {
        hideContextMenus()
        return
    }
    
    try {
        const res = await fetch('/delete-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user: currentUser,
                chat_with: selectedChatPhone
            })
        })
        
        if (res.ok) {
            const cleanPhone = cleanPhone(selectedChatPhone)
            const chatElement = document.getElementById(`chat-${cleanPhone}`)
            if (chatElement) {
                chatElement.remove()
            }
            
            if (currentChat === selectedChatPhone) {
                currentChat = null
                document.getElementById('emptyChat').style.display = 'flex'
                document.getElementById('chatBlock').style.display = 'none'
            }
            
            const count = document.getElementById("chatsCount")
            count.textContent = parseInt(count.textContent) - 1
            
            delete chatsCache[selectedChatPhone]
            
            showToast('Чат удален')
        }
        
    } catch (error) {
        console.error("Error deleting chat:", error)
        showToast("Ошибка при удалении чата")
    }
    
    hideContextMenus()
}

// Заглушить чат
function muteChat() {
    if (!selectedChatPhone) return
    showToast('Чат заглушен')
    hideContextMenus()
}

// Очистить историю чата
async function clearChat() {
    if (!selectedChatPhone) return
    
    if (!confirm('Очистить историю сообщений?')) {
        hideContextMenus()
        return
    }
    
    try {
        const res = await fetch('/clear-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user: currentUser,
                chat_with: selectedChatPhone
            })
        })
        
        if (res.ok) {
            if (currentChat === selectedChatPhone) {
                document.getElementById("messages").innerHTML = ""
            }
            
            const cleanPhone = cleanPhone(selectedChatPhone)
            const chatElement = document.getElementById(`chat-${cleanPhone}`)
            if (chatElement) {
                const lastMsgElement = chatElement.querySelector('.chat-last-message')
                if (lastMsgElement) {
                    lastMsgElement.innerText = 'Нет сообщений'
                }
                
                const badge = chatElement.querySelector('.unread-badge')
                if (badge) {
                    badge.remove()
                }
            }
            
            if (chatsCache[selectedChatPhone]) {
                chatsCache[selectedChatPhone].last = ''
            }
            
            showToast('История очищена')
        }
        
    } catch (error) {
        console.error("Error clearing chat:", error)
        showToast("Ошибка при очистке")
    }
    
    hideContextMenus()
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
