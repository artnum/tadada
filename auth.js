function TaDaDaJS (path = '.auth', base = null) {
    this.halgo = 'SHA-256'
    this.halgo_length = 256
    this.pbkdf2_iterations = [100000, 200000]
    this.base = base || window.location
    this.path = path
}

TaDaDaJS.prototype.getUserid = function (username) {
    return new Promise((resolve, reject) => {
        fetch (new URL(`${this.path}/userid`, this.base), {method: 'POST', body: JSON.stringify({username})})
        .then(response => {
            if (!response.ok) { return reject(new Error('login error')) }
            return response.json()
        })
        .then(result => {
            if (result.error) { return reject(new Error('login error')) }
            resolve(result.userid)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.init = function (userid) {
    return new Promise((resolve, reject) => {
        fetch (new URL(`${this.path}/init`, this.base), {method: 'POST', body: JSON.stringify({userid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('login error')) }
            return response.json()
        })
        .then(result => {
            if (result.error) { return reject(new Error('login error')) }
            resolve(result)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.arrayToB64 = function (array) {
    return btoa(String.fromCharCode(...new Uint8Array(array)))
}

TaDaDaJS.prototype.b64ToArray = function (string) {
    const binary = atob(string)
    const array = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        array[i] = binary.charCodeAt(i)
    }
    return array.buffer
}

TaDaDaJS.prototype.genPassword = function (password) {
    const getRandomInt = function (min, max) {
        min = Math.ceil(min);
        max = Math.floor(max);
        return Math.floor(Math.random() * (max - min) + min);
    }
    return new Promise((resolve, reject) => {
        const outKey = {
            derived: '',
            salt: new Uint8Array(this.halgo_length / 8),
            iterations: getRandomInt(this.pbkdf2_iterations[0], this.pbkdf2_iterations[1])
        }
        crypto.getRandomValues(outKey.salt)
        crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
        .then(cryptokey => {
            return crypto.subtle.deriveKey({name: 'PBKDF2', hash: this.halgo, salt: outKey.salt, iterations: outKey.iterations}, 
                cryptokey, {name: 'HMAC', hash: this.halgo, length: this.halgo_length}, true, ['sign'])
        })
        .then(cryptokey => {
            return crypto.subtle.exportKey('raw', cryptokey)
        })
        .then(rawkey => {
            outKey.derived = this.arrayToB64(rawkey)
            outKey.salt = this.arrayToB64(outKey.salt)
            return resolve(outKey)
        })
        .catch(e => {
            reject(new Error('Password generation failed', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.genToken = function (params, password) {
    return new Promise ((resolve, reject) => {
        crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
        .then(cryptokey => {
            const salt = this.b64ToArray(params.salt)
            if (params.halgo_length) { this.halgo_length = parseInt(params.halgo_length) }
            if (params.halgo) { this.halgo = params.halgo }
            return crypto.subtle.deriveKey({name: 'PBKDF2', hash: this.halgo, salt: salt, iterations: parseInt(params.count)}, 
                cryptokey, {name: 'HMAC', hash: this.halgo, length: this.halgo_length}, false, ['sign'])
        })
        .then(key => {
            return crypto.subtle.sign({name: 'HMAC', hash: this.halgo, length: this.halgo_length}, key, this.b64ToArray(params.auth))
        })
        .then(rawtoken => {
            resolve(this.arrayToB64(rawtoken))
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.getToken = function () {
    return Promise.resolve(localStorage.getItem('TaDaDaJS-token'))
}

TaDaDaJS.prototype.getUser = function () {
    return Promise.resolve(localStorage.getItem('TaDaDaJS-userid'))
}

TaDaDaJS.prototype.check = function (token) {
    return new Promise((resolve, reject) => {
        fetch (new URL(`${this.path}/check`, this.base), {method: 'POST', body: JSON.stringify({auth: token})})
        .then(response => {
            if (!response.ok) { return reject(new Error('login error')) }
            return response.json()
        })
        .then(result => {
            if (!result.done) { return reject(new Error('login error'))}
            resolve(token)
        })
    })
}

TaDaDaJS.prototype.getShareableToken = function (url, comment = '', duration = 86400) {
    return new Promise((resolve, reject) => {
        this.getToken()
        .then(token => {
            return fetch(new URL(`${this.path}/getshareable`, this.base), {method: 'POST', body: JSON.stringify({auth: token, url, comment, permanent: duration <= 0, duration})})
        })
        .then(response => {
            if (!response.ok) { return reject(new Error('login error')) }
            return response.json()
        })
        .then(result => {
            if (!result.done) { return reject(new Error('login error'))}
            return resolve(result.token)
        })
        .catch(e => {
            return reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.quit = function (token) {
    return fetch(new URL(`${this.path}/quit`, this.base), {method: 'POST', body: JSON.stringify({auth: token})})
}

TaDaDaJS.prototype.logout = function () {
    return new Promise(resolve => {
        const token = localStorage.getItem('TaDaDaJS-token')
        this.quit(token)
        .finally(() => {
            localStorage.removeItem('TaDaDaJS-token')
            localStorage.removeItem('TaDaDaJS-userid')
            resolve()
        })
    })
}

TaDaDaJS.prototype.login = function (userid, password) {
    return new Promise((resolve, reject) => {
        this.init(userid)
        .then(params => {
            return this.genToken(params, password)
        })
        .then(token => {
            return this.check(token)
        })
        .then(token => {
            localStorage.setItem('TaDaDaJS-userid', userid)
            localStorage.setItem('TaDaDaJS-token', token)
            resolve(token)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.disconnect = function (userid) {
    return new Promise((resolve, reject) => {
        return fetch (new URL(`${this.path}/disconnect`, this.base), {method: 'POST', body: JSON.stringify({userid: userid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('Cannot disconnect')) }
            return response.json()
        })
        .then(result => {
            resolve(result.userid)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.disconnectAll = function (userid) {
    return new Promise((resolve, reject) => {
        return fetch (new URL(`${this.path}/disconnect-all`, this.base), {method: 'POST', body: JSON.stringify({userid: userid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('Cannot disconnect')) }
            return response.json()
        })
        .then(result => {
            resolve(result.userid)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.disconnectShare = function (userid) {
    return new Promise((resolve, reject) => {
        return fetch (new URL(`${this.path}/disconnect-share`, this.base), {method: 'POST', body: JSON.stringify({userid: userid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('Cannot disconnect')) }
            return response.json()
        })
        .then(result => {
            resolve(result.userid)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.disconnectById = function (uid) {
    return new Promise((resolve, reject) => {
        return fetch (new URL(`${this.path}/disconnect-by-id`, this.base), {method: 'POST', body: JSON.stringify({uid: uid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('Cannot disconnect')) }
            return response.json()
        })
        .then(result => {
            resolve(result.userid)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.getActive = function (userid) {
    return new Promise((resolve, reject) => {
        fetch (new URL(`${this.path}/active`, this.base), {method: 'POST', body: JSON.stringify({userid: userid})})
        .then(response => {
            if (!response.ok) { return reject(new Error('Cannot get active connection')) }
            return response.json()
        })
        .then(result => {
            if (!result.connections) { return reject(new Error('Cannot get active connection'))}
            resolve(result.connections)
        })
        .catch(e => {
            reject(new Error('login error', {cause: e}))
        })
    })
}