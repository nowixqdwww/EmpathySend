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

// Для редактора аватара
let cropper = null
let currentAvatarFile = null

// Глобальный объект для хранения онлайн статусов
window.clients = {}

// Хранилище чатов и непрочитанных сообщений
let chatsCache = {}
let unreadCounts = {}

// ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============

function cleanPhone(phone) {
    if (!phone) return ''
    return phone.toString().replace(/\s+/g, '').trim()
}

function chatExists(phone) {
    const cleanPhoneValue = cleanPhone(phone)
    return document.getElementById(`chat-${cleanPhoneValue}`) !== null
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
    if (!name) return '<i class="fas fa-user"></i>'
    if (name.startsWith('@') && name.length > 1) {
        return name[1].toUpperCase()
    }
    if (name.length > 0) {
        return name[0].toUpperCase()
    }
    return '<i class="fas fa-user"></i>'
}

function escapeHtml(text) {
    const div = document.createElement('div')
    div.textContent = text
    return div.innerHTML
}

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
        document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
        document.getElementById('chatUserStatus').className = `chat-user-status ${isOnline ? '' : 'offline'}`
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
    };
    
    // Обновляем требования
    const reqLength = document.getElementById('reqLength')
    const reqNumber = document.getElementById('reqNumber')
    const reqLetter = document.getElementById('reqLetter')
    const strengthBar = document.getElementById('strengthBar')
    const saveBtn = document.getElementById('savePasswordBtn')
    
    if (reqLength) {
        reqLength.innerHTML = (strength.length ? '✅' : '❌') + ' Минимум 6 символов';
        reqLength.className = 'requirement' + (strength.length ? ' met' : '');
    }
    
    if (reqNumber) {
        reqNumber.innerHTML = (strength.number ? '✅' : '❌') + ' Хотя бы одна цифра';
        reqNumber.className = 'requirement' + (strength.number ? ' met' : '');
    }
    
    if (reqLetter) {
        reqLetter.innerHTML = (strength.letter ? '✅' : '❌') + ' Хотя бы одна буква';
        reqLetter.className = 'requirement' + (strength.letter ? ' met' : '');
    }
    
    // Определяем общую силу пароля
    const score = Object.values(strength).filter(Boolean).length;
    
    if (strengthBar) {
        strengthBar.className = 'strength-bar';
        if (score === 3) {
            strengthBar.classList.add('strong');
        } else if (score === 2) {
            strengthBar.classList.add('medium');
        } else if (score >= 1) {
            strengthBar.classList.add('weak');
        }
    }
    
    // Активируем кнопку если все требования выполнены
    if (saveBtn) {
        saveBtn.disabled = !(strength.length && strength.number && strength.letter);
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

    // Форматируем номер
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

        if (data.error) {
            showToast(data.error)
            return
        }

        showToast('Регистрация успешна! Теперь войдите')
        showLoginForm()
        document.getElementById('loginPhone').value = cleanPhone

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

    // Форматируем номер
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

        if (data.error) {
            // Проверяем, существует ли пользователь вообще
            const userCheck = await fetch(`/user/${cleanPhone}`)
            
            if (userCheck.ok) {
                // Пользователь существует, но пароль неверный
                // Возможно, у него вообще нет пароля
                const userData = await userCheck.json()
                
                // Проверяем, есть ли у пользователя пароль (можно через отдельный эндпоинт)
                const passwordCheck = await fetch(`/check-password/${cleanPhone}`)
                const passwordData = await passwordCheck.json()
                
                if (!passwordData.hasPassword) {
                    // У пользователя нет пароля - предлагаем создать
                    if (confirm('У этого аккаунта еще нет пароля. Хотите создать пароль?')) {
                        currentUser = cleanPhone
                        showPasswordSetup()
                        return
                    }
                }
            }
            
            showToast(data.error)
            return
        }

        currentUser = data.phone
        completeLogin()

    } catch (error) {
        console.error('Login error:', error)
        showToast('Ошибка входа')
    }
}
function completeLogin() {
    document.getElementById('loginScreen').style.display = 'none'
    document.getElementById('app').style.display = 'flex'
    document.getElementById('sidebar').classList.add('open')

    document.getElementById('myPhone').innerText = formatPhone(currentUser)
    
    loadUserProfile()
    connect()
    loadChats()
}

// ============= ФУНКЦИИ ДЛЯ СМЕНЫ ПАРОЛЯ =============

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
            myAvatar.innerHTML = `<img src="${data.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerHTML='<i class=\'fas fa-user\'></i>'">`
        } else {
            myAvatar.innerHTML = '<i class="fas fa-user"></i>'
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
            modalAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerHTML='<i class=\'fas fa-user\'></i>'">`
        } else {
            modalAvatar.innerHTML = '<i class="fas fa-user"></i>'
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
                    previewAvatar.innerHTML = '<i class="fas fa-user"></i>'
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
        
        currentAvatarFile = file
        
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
        
        document.getElementById('previewAvatarText').innerHTML = '<i class="fas fa-user"></i>'
        document.getElementById('avatarInput').value = ''
        
        closeAvatarEditor()
        
        await loadUserProfile()
        loadChats()
        
    } catch (error) {
        console.error('Error removing avatar:', error)
        showToast('Ошибка удаления')
    }
}

// ============= ФУНКЦИИ ДЛЯ ЧАТОВ =============

function createChatElement(chat) {
    const displayName = chat.displayName || chat.name || chat.username || chat.phone
    const lastMessage = chat.last || 'Нет сообщений'
    const unreadCount = chat.unread || 0
    
    let div = document.createElement('div')
    div.className = 'chatItem'
    div.id = `chat-${cleanPhone(chat.phone)}`
    
    if (chat.phone === currentChat) {
        div.classList.add('active')
    }
    
    let avatarHtml
    if (chat.avatar) {
        avatarHtml = `<img src="${chat.avatar}" class="chat-avatar-img" alt="avatar" onerror="this.onerror=null; this.parentElement.innerHTML='<i class=\'fas fa-user\'></i>'">`
    } else {
        avatarHtml = '<i class="fas fa-user"></i>'
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

async function loadChats() {
    if (!currentUser) return
    
    try {
        let res = await fetch(`/users/${currentUser}`)
        if (!res.ok) throw new Error('Failed to load chats')
        
        let chats = await res.json()
        
        let list = document.getElementById('chatList')
        list.innerHTML = ''
        
        document.getElementById('chatsCount').textContent = chats.length
        
        chats.sort((a, b) => {
            if (!a.last) return 1
            if (!b.last) return -1
            return 0
        })
        
        chats.forEach(chat => {
            list.appendChild(createChatElement(chat))
        })
        
    } catch (error) {
        console.error('Error loading chats:', error)
        showToast('Ошибка загрузки чатов')
    }
}

function openChat(phone, displayName) {
    if (currentChat === phone) return
    
    currentChat = phone
    
    fetch(`/user/${phone}`)
        .then(res => res.json())
        .then(user => {
            const name = user.name || user.username || phone
            document.getElementById('chatUserName').innerText = name
            document.getElementById('chatUserPhone').innerText = formatPhone(phone)
            
            const chatAvatar = document.getElementById('chatAvatarText')
            if (user.avatar) {
                chatAvatar.innerHTML = `<img src="${user.avatar}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;" onerror="this.onerror=null; this.parentElement.innerHTML='<i class=\'fas fa-user\'></i>'">`
            } else {
                chatAvatar.innerHTML = '<i class="fas fa-user"></i>'
            }
            
            const isOnline = window.clients && window.clients[phone] === true
            document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
            document.getElementById('chatUserStatus').className = `chat-user-status ${isOnline ? '' : 'offline'}`
        })
        .catch(() => {
            document.getElementById('chatUserName').innerText = displayName || phone
            document.getElementById('chatUserPhone').innerText = formatPhone(phone)
            document.getElementById('chatAvatarText').innerHTML = '<i class="fas fa-user"></i>'
        })
    
    document.getElementById('emptyChat').style.display = 'none'
    document.getElementById('chatBlock').style.display = 'flex'
    
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('open')
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
        showToast('Нет соединения с сервером')
        return
    }

    ws.send(JSON.stringify({
        action: 'history',
        user: currentChat
    }))
}

function send() {
    if (!currentChat) {
        showToast('Выберите чат')
        return
    }

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        showToast('Нет соединения с сервером')
        return
    }

    const text = document.getElementById('text').value.trim()

    if (!text) return

    ws.send(JSON.stringify({
        action: 'send',
        to: currentChat,
        text: text
    }))

    document.getElementById('text').value = ''
}

function addMessage(user, text, messageId = null) {
    const messagesDiv = document.getElementById('messages')
    const div = document.createElement('div')
    
    div.className = 'message ' + (user === currentUser ? 'me' : 'other')
    
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
        
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault()
            showContextMenu(e, 'message', { messageId, element: div })
        })
        
        div.addEventListener('touchstart', (e) => {
            e.preventDefault()
            touchTimeout = setTimeout(() => {
                isLongPress = true
                if (window.navigator.vibrate) window.navigator.vibrate(50)
                showContextMenu(e, 'message', { messageId, element: div })
            }, 500)
        })
        
        div.addEventListener('touchend', () => {
            clearTimeout(touchTimeout)
        })
        
        div.addEventListener('touchmove', () => {
            clearTimeout(touchTimeout)
            isLongPress = true
        })
    }
    
    messagesDiv.appendChild(div)
    messagesDiv.scrollTop = messagesDiv.scrollHeight
}

// ============= КОНТЕКСТНОЕ МЕНЮ =============

function showContextMenu(event, type, data) {
    event.preventDefault()
    event.stopPropagation()
    
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    
    let menuId
    
    if (type === 'message') {
        menuId = 'messageContextMenu'
        selectedMessageId = data.messageId
        selectedMessageElement = data.element
    } else {
        menuId = 'chatContextMenu'
        selectedChatPhone = data.phone
        selectedChatElement = data.element
    }
    
    const menu = document.getElementById(menuId)
    
    let x, y
    if (event.touches) {
        x = event.touches[0].pageX
        y = event.touches[0].pageY
    } else {
        x = event.pageX
        y = event.pageY
    }
    
    menu.style.display = 'block'
    menu.style.left = x + 'px'
    menu.style.top = y + 'px'
}

function hideContextMenus() {
    document.getElementById('messageContextMenu').style.display = 'none'
    document.getElementById('chatContextMenu').style.display = 'none'
    selectedMessageId = null
    selectedMessageElement = null
    selectedChatPhone = null
    selectedChatElement = null
}

async function deleteMessage() {
    if (!selectedMessageId || !currentChat) return
    
    try {
        const res = await fetch(`/message/${selectedMessageId}?user=${currentUser}`, {
            method: 'DELETE'
        })
        
        if (res.ok && selectedMessageElement) {
            selectedMessageElement.remove()
            showToast('Сообщение удалено')
        }
        
    } catch (error) {
        console.error('Error deleting message:', error)
        showToast('Ошибка при удалении')
    }
    
    hideContextMenus()
}

async function deleteChat() {
    if (!selectedChatPhone) return
    
    if (!confirm('Удалить этот чат?')) return
    
    try {
        const res = await fetch(`/chat/${currentUser}/${selectedChatPhone}`, {
            method: 'DELETE'
        })
        
        if (res.ok) {
            const element = document.getElementById(`chat-${cleanPhone(selectedChatPhone)}`)
            if (element) element.remove()
            
            if (currentChat === selectedChatPhone) {
                currentChat = null
                document.getElementById('emptyChat').style.display = 'flex'
                document.getElementById('chatBlock').style.display = 'none'
            }
            
            showToast('Чат удален')
        }
        
    } catch (error) {
        console.error('Error deleting chat:', error)
        showToast('Ошибка при удалении')
    }
    
    hideContextMenus()
}

function muteChat() {
    if (!selectedChatPhone) return
    showToast('Чат заглушен')
    hideContextMenus()
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
                }
            }

            if (data.action === 'message') {
                addMessage(data.from, data.text, data.id)
                
                const cleanFrom = cleanPhone(data.from)
                const existingChat = document.getElementById(`chat-${cleanFrom}`)
                
                if (!existingChat) {
                    loadChats()
                } else {
                    const list = document.getElementById('chatList')
                    list.prepend(existingChat)
                    
                    const lastMsgElement = existingChat.querySelector('.chat-last-message')
                    if (lastMsgElement) {
                        lastMsgElement.innerText = data.text
                    }
                }
                
                if (currentChat !== data.from) {
                    showToast('Новое сообщение')
                    if (window.navigator.vibrate) window.navigator.vibrate(200)
                }
            }

            if (data.action === 'message_sent') {
                addMessage(currentUser, data.text, data.id)
            }

            if (data.action === 'history') {
                document.getElementById('messages').innerHTML = ''
                data.messages.forEach(m => {
                    addMessage(m[1], m[2], m[0])
                })
            }

            if (data.action === 'typing') {
                if (currentChat === data.from) {
                    document.getElementById('chatUserStatus').textContent = 'печатает...'
                    clearTimeout(window.typingStatusTimeout)
                    window.typingStatusTimeout = setTimeout(() => {
                        if (currentChat === data.from) {
                            const isOnline = window.clients && window.clients[data.from]
                            document.getElementById('chatUserStatus').textContent = isOnline ? 'online' : 'offline'
                        }
                    }, 3000)
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
            avatarHtml = '<i class="fas fa-user"></i>'
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

// ============= НАСТРОЙКИ =============

function openSettings() {
    const modal = document.getElementById('settingsModal')
    
    // Добавляем кнопку смены пароля в настройки
    const securitySection = document.querySelector('.settings-section:nth-child(2)')
    if (!document.getElementById('changePasswordBtn')) {
        const passwordItem = document.createElement('div')
        passwordItem.className = 'settings-item'
        passwordItem.id = 'changePasswordBtn'
        passwordItem.innerHTML = `
            <div class="settings-item-info">
                <div class="settings-item-title">Пароль</div>
                <div class="settings-item-description">Изменить пароль для входа</div>
            </div>
            <button class="settings-button" onclick="openChangePassword()">
                <i class="fas fa-key"></i> Сменить
            </button>
        `
        securitySection.insertBefore(passwordItem, securitySection.firstChild)
    }
    
    loadPrivacySettings()
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

document.getElementById('text').addEventListener('input', () => {
    if (!currentChat || !ws || ws.readyState !== WebSocket.OPEN) return
    
    clearTimeout(typingTimeout)
    
    ws.send(JSON.stringify({
        action: 'typing',
        to: currentChat
    }))
    
    typingTimeout = setTimeout(() => {}, 2000)
})

// ============= ОБРАБОТЧИКИ СОБЫТИЙ =============

document.addEventListener('click', hideContextMenus)
document.addEventListener('touchstart', hideContextMenus)

document.addEventListener('contextmenu', (e) => {
    if (hasClass(e.target, 'message') || hasClass(e.target, 'chatItem')) {
        e.preventDefault()
    }
})

document.getElementById('text').addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        send()
    }
})

document.getElementById('searchUser').addEventListener('input', (e) => {
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

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal()
        closeAvatarEditor()
        closeChangePassword()
    }
})

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPhone').focus()
})

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

// Очистка при закрытии
window.addEventListener('beforeunload', () => {
    if (pingInterval) clearInterval(pingInterval)
    if (reconnectTimeout) clearTimeout(reconnectTimeout)
    if (ws) ws.close(1000, 'Page closed')
})

// Периодическое обновление статусов
setInterval(updateOnlineStatus, 5000)

