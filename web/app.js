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

// Для поиска
let searchTimeout = null

// Глобальный объект для хранения онлайн статусов
window.clients = {}

// Хранилище чатов и непрочитанных сообщений
let chatsCache = {}
let unreadCounts = {}

// ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============

// Функция очистки номера от пробелов
function cleanPhone(phone) {
    if (!phone) return ''
    return phone.toString().replace(/\s+/g, '').trim()
}

// Проверка, существует ли чат в списке
function chatExists(phone) {
    const cleanPhoneValue = cleanPhone(phone)
    return document.getElementById(`chat-${cleanPhoneValue}`) !== null
}

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

// Универсальная функция для проверки наличия класса у элемента или его родителей
function hasClass(element, className) {
    if (!element) return false;
    let current = element;
    while (current) {
        if (current.classList && current.classList.contains(className)) {
            return true;
        }
        current = current.parentElement;
    }
    return false;
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

// ============= ФУНКЦИИ ДЛЯ СТАТУСОВ =============

// Обновление статусов онлайн
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
        document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
        document.getElementById('chatUserStatus').className = `chat-user-status ${isOnline ? '' : 'offline'}`
    }
}

// Трансляция статуса онлайн всем контактам
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

// ============= ФУНКЦИИ ДЛЯ КОНТЕКСТНОГО МЕНЮ =============

function showContextMenu(event, type, data) {
    event.preventDefault()
    event.stopPropagation()
    
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
    
    let x, y
    
    if (event.touches) {
        x = event.touches[0].pageX
        y = event.touches[0].pageY
        event.preventDefault()
    } else {
        x = event.pageX
        y = event.pageY
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
    selectedChatPhone = null
    selectedChatElement = null
}

document.addEventListener('click', hideContextMenus)
document.addEventListener('touchstart', hideContextMenus)

document.addEventListener('contextmenu', (e) => {
    if (hasClass(e.target, 'message') || hasClass(e.target, 'chatItem')) {
        e.preventDefault();
    }
});

document.addEventListener('selectstart', (e) => {
    if (hasClass(e.target, 'message') || hasClass(e.target, 'chatItem')) {
        e.preventDefault();
    }
});

// ============= ФУНКЦИИ ДЛЯ РАБОТЫ С ЧАТАМИ =============

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

function createChatElement(chat) {
    const displayName = chat.displayName || chat.name || chat.username || chat.phone
    const lastMessage = chat.last || 'Нет сообщений'
    const unreadCount = unreadCounts[chat.phone] || 0
    
    let div = document.createElement("div")
    div.className = "chatItem"
    
    const cleanPhoneValue = cleanPhone(chat.phone)
    div.id = `chat-${cleanPhoneValue}`
    
    if (chat.phone === currentChat) {
        div.classList.add('active')
    }
    
    let avatarHtml
    if (chat.avatar) {
        avatarHtml = `<img src="${chat.avatar}" class="chat-avatar-img" alt="avatar" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
    } else {
        avatarHtml = escapeHtml(getAvatarLetter(displayName))
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

function renderChatList(chats) {
    let list = document.getElementById("chatList")
    list.innerHTML = ""

    document.getElementById('chatsCount').textContent = chats.length

    chats.forEach(chat => {
        const chatElement = createChatElement(chat)
        list.appendChild(chatElement)
    })
}

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
        
        setTimeout(removeDuplicateChats, 100)
        
    } catch (error) {
        console.error("Error loading chats:", error)
        showToast("Ошибка загрузки чатов")
    }
}

async function updateSingleChat(phone, moveToTop = false) {
    try {
        const cleanPhoneValue = cleanPhone(phone)
        
        const existingElement = document.getElementById(`chat-${cleanPhoneValue}`)
        
        const res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')
        
        const chats = await res.json()
        const updatedChat = chats.find(c => cleanPhone(c.phone) === cleanPhoneValue)
        
        if (!updatedChat || !updatedChat.last) {
            return
        }
        
        updatedChat.unread = unreadCounts[phone] || 0
        chatsCache[phone] = updatedChat
        
        const list = document.getElementById("chatList")
        let chatElement = document.getElementById(`chat-${cleanPhoneValue}`)
        
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
            
            const isOnline = window.clients && window.clients[phone] === true
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
            if (updatedChat.last) {
                const newChat = createChatElement(updatedChat)
                if (moveToTop) {
                    list.prepend(newChat)
                } else {
                    list.appendChild(newChat)
                }
                
                const count = document.getElementById("chatsCount")
                count.textContent = parseInt(count.textContent) + 1
            }
        }
        
        setTimeout(removeDuplicateChats, 50)
        
    } catch (error) {
        console.error("Error updating single chat:", error)
    }
}

// ============= ФУНКЦИИ ДЛЯ АВТОРИЗАЦИИ И ПРОФИЛЯ =============

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
            myAvatar.innerHTML = `<img src="${data.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerText=getAvatarLetter('${displayName}')">`
        } else {
            myAvatar.innerText = getAvatarLetter(displayName)
        }
        
    } catch (error) {
        console.error("Error loading profile:", error)
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
        
        const isOnline = window.clients && window.clients[phone] === true
        
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

function cancelEdit() {
    document.getElementById('profileView').style.display = 'block'
    document.getElementById('profileEdit').style.display = 'none'
}

function closeModal() {
    document.getElementById('profileModal').classList.remove('show')
}

// ============= ФУНКЦИИ ДЛЯ ЧАТА И СООБЩЕНИЙ =============

function openChat(phone, displayName) {
    if (currentChat === phone) return
    
    currentChat = phone
    
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
            
            const isOnline = window.clients && window.clients[phone] === true
            document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
            document.getElementById('chatUserStatus').className = `chat-user-status ${isOnline ? '' : 'offline'}`
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
    
    const cleanPhoneValue = cleanPhone(phone)
    const activeChat = document.getElementById(`chat-${cleanPhoneValue}`)
    if (activeChat) {
        activeChat.classList.add('active')
    }
}

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
    
    updateSingleChat(currentChat, true)
}

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
        let isLongPress = false
        let touchTimeout
        
        div.addEventListener('mousedown', () => {
            isLongPress = false
        })
        
        div.addEventListener('mouseup', (e) => {
            if (!isLongPress && e.button === 0) {
            }
        })
        
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault()
            e.stopPropagation()
            showContextMenu(e, 'message', { messageId: messageId, element: div })
        })
        
        div.addEventListener('touchstart', (e) => {
            e.preventDefault()
            isLongPress = false
            
            const touch = e.touches[0]
            const startX = touch.clientX
            const startY = touch.clientY
            
            touchTimeout = setTimeout(() => {
                isLongPress = true
                if (window.navigator.vibrate) {
                    window.navigator.vibrate(50)
                }
                showContextMenu(e, 'message', { messageId: messageId, element: div })
            }, 500)
            
            const onTouchMove = (moveEvent) => {
                const moveTouch = moveEvent.touches[0]
                const moveX = moveTouch.clientX
                const moveY = moveTouch.clientY
                
                if (Math.abs(moveX - startX) > 10 || Math.abs(moveY - startY) > 10) {
                    clearTimeout(touchTimeout)
                    isLongPress = true
                    div.removeEventListener('touchmove', onTouchMove)
                }
            }
            
            div.addEventListener('touchmove', onTouchMove, { passive: false })
            
            div.addEventListener('touchend', () => {
                clearTimeout(touchTimeout)
                div.removeEventListener('touchmove', onTouchMove)
                
                if (!isLongPress) {
                }
            }, { once: true })
            
            div.addEventListener('touchcancel', () => {
                clearTimeout(touchTimeout)
                div.removeEventListener('touchmove', onTouchMove)
            }, { once: true })
        }, { passive: false })
    }
    
    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

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
        
        await updateSingleChat(currentChat, true)
        
        showToast('Сообщение удалено')
        
    } catch (error) {
        console.error("Error deleting message:", error)
        showToast("Ошибка при удалении")
    }
    
    hideContextMenus()
}

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
            const cleanPhoneValue = cleanPhone(selectedChatPhone)
            const chatElement = document.getElementById(`chat-${cleanPhoneValue}`)
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

function muteChat() {
    if (!selectedChatPhone) return
    showToast('Чат заглушен')
    hideContextMenus()
}

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
            
            const cleanPhoneValue = cleanPhone(selectedChatPhone)
            const chatElement = document.getElementById(`chat-${cleanPhoneValue}`)
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

// ============= WEBSOCKET ФУНКЦИИ =============

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
            try {
                const data = JSON.parse(event.data)

                if (data.action === 'pong') return

                if (data.action === "status") {
                    if (data.from) {
                        if (!window.clients) window.clients = {}
                        window.clients[data.from] = data.online
                        
                        const contactId = `chat-${cleanPhone(data.from)}`
                        const chatElement = document.getElementById(contactId)
                        if (chatElement) {
                            const statusDot = chatElement.querySelector('.chat-status')
                            if (statusDot) {
                                statusDot.className = `chat-status ${data.online ? '' : 'offline'}`
                            }
                        }
                        
                        if (currentChat === data.from) {
                            document.getElementById('chatUserStatus').textContent = data.online ? 'online' : 'offline'
                            document.getElementById('chatUserStatus').className = `chat-user-status ${data.online ? '' : 'offline'}`
                        }
                        
                        if (data.from === currentUser) {
                            const modalStatus = document.getElementById('modalStatus')
                            if (modalStatus) {
                                modalStatus.innerHTML = data.online ? 
                                    '<span style="color: #4ade80;">● Онлайн</span>' : 
                                    '<span style="color: #f87171;">● Оффлайн</span>'
                            }
                        }
                    }
                }

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
                    
                    if (data.from) {
                        updateSingleChat(data.from, true)
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
                        document.getElementById('chatUserStatus').className = 'chat-user-status'
                        clearTimeout(window.typingStatusTimeout)
                        window.typingStatusTimeout = setTimeout(() => {
                            if (currentChat === data.from) {
                                const isOnline = window.clients && window.clients[data.from] === true
                                document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
                                document.getElementById('chatUserStatus').className = `chat-user-status ${isOnline ? '' : 'offline'}`
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
            
            broadcastOnlineStatus(false)
            
            if (window.clients) {
                Object.keys(window.clients).forEach(key => {
                    window.clients[key] = false
                })
            }
            
            isConnected = false
            if (pingInterval) clearInterval(pingInterval)
            
            updateOnlineStatus()
            
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

// ============= ПОИСК С АВТОДОПОЛНЕНИЕМ =============

// Поиск пользователей по части имени
async function searchUsers(query) {
    if (query.length < 2) {
        hideSearchResults()
        return
    }
    
    try {
        const res = await fetch(`/search-users/${encodeURIComponent(query)}`)
        if (!res.ok) throw new Error('Search failed')
        
        const data = await res.json()
        displaySearchResults(data.users, query)
        
    } catch (error) {
        console.error("Search error:", error)
    }
}

// Отображение результатов поиска
function displaySearchResults(users, query) {
    const resultsDiv = document.getElementById('searchResults')
    const searchInput = document.getElementById('searchUser')
    
    if (!resultsDiv) return
    
    resultsDiv.innerHTML = ''
    
    if (users.length === 0) {
        resultsDiv.innerHTML = '<div class="search-no-results">Ничего не найдено</div>'
        resultsDiv.style.display = 'block'
        return
    }
    
    users.forEach(user => {
        const item = createSearchResultItem(user, query)
        resultsDiv.appendChild(item)
    })
    
    resultsDiv.style.display = 'block'
}

// Создание элемента результата поиска
function createSearchResultItem(user, query) {
    const div = document.createElement('div')
    div.className = 'search-result-item'
    
    // Подсвечиваем совпадения
    const highlightedUsername = highlightMatch(user.username || '', query)
    const highlightedName = highlightMatch(user.name || '', query)
    
    let avatarHtml
    if (user.avatar) {
        avatarHtml = `<img src="${user.avatar}" alt="avatar">`
    } else {
        avatarHtml = getAvatarLetter(user.displayName || user.username || user.phone)
    }
    
    div.innerHTML = `
        <div class="search-result-avatar">${avatarHtml}</div>
        <div class="search-result-info">
            <div class="search-result-name">${highlightedName || user.displayName || user.phone}</div>
            <div class="search-result-username">${highlightedUsername || ''}</div>
            <div class="search-result-phone">${formatPhone(user.phone)}</div>
        </div>
    `
    
    div.onclick = () => {
        document.getElementById('searchUser').value = user.username || user.name || ''
        hideSearchResults()
        showUserProfile(user.phone, false)
    }
    
    return div
}

// Подсветка совпадений
function highlightMatch(text, query) {
    if (!text || !query) return text
    
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
    return text.replace(regex, '<span style="background-color: #ffeb3b; color: #333;">$1</span>')
}

// Обработчик ввода в поле поиска
document.getElementById('searchUser').addEventListener('input', (e) => {
    const query = e.target.value.trim()
    
    if (searchTimeout) {
        clearTimeout(searchTimeout)
    }
    
    if (query.length < 2) {
        hideSearchResults()
        return
    }
    
    const resultsDiv = document.getElementById('searchResults')
    resultsDiv.innerHTML = '<div class="search-loading">Поиск...</div>'
    resultsDiv.style.display = 'block'
    
    searchTimeout = setTimeout(() => {
        searchUsers(query)
    }, 300)
})

// Обработчик клика вне области поиска
document.addEventListener('click', (e) => {
    const searchInput = document.getElementById('searchUser')
    const searchResults = document.getElementById('searchResults')
    
    if (searchInput && searchResults) {
        if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
            hideSearchResults()
        }
    }
})

// Скрыть результаты поиска
function hideSearchResults() {
    const resultsDiv = document.getElementById('searchResults')
    if (resultsDiv) {
        resultsDiv.style.display = 'none'
    }
}

// Обработчик клавиш в поиске
document.getElementById('searchUser').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideSearchResults()
        e.target.value = ''
    } else if (e.key === 'Enter') {
        const query = e.target.value.trim()
        if (query) {
            searchExactUser(query)
        }
    }
})

// Поиск точного пользователя
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

        if (!res.ok) throw new Error('Search failed')
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

// ============= ИНДИКАТОР ПЕЧАТАНИЯ =============

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

// ============= ОБРАБОТЧИКИ СОБЫТИЙ =============

document.getElementById("text").addEventListener("keypress", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault()
        send()
    }
})

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal()
    }
})

window.onclick = function(event) {
    const modal = document.getElementById('profileModal')
    if (event.target === modal) {
        closeModal()
    }
}

window.addEventListener('online', () => {
    showToast('Соединение восстановлено')
    if (!isConnected && currentUser) {
        connect()
    }
})

window.addEventListener('offline', () => {
    showToast('Потеряно соединение с интернетом')
    if (window.clients) {
        Object.keys(window.clients).forEach(key => {
            window.clients[key] = false
        })
    }
    updateOnlineStatus()
})

window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        document.getElementById('sidebar').classList.remove('open')
    }
})

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPhone').focus()
})

window.addEventListener('beforeunload', () => {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)
    if (ws) ws.close(1000, 'Page closed')
})

setInterval(updateOnlineStatus, 5000)
