function TaDaDaJSKV() {
    this._kvstore = null
}

TaDaDaJSKV.prototype._initKVStore = function () {
    this._kvstore = new Promise((resolve, reject) => {
        const request = indexedDB.open('tadadajskv', 1)
        request.onerror = (event) => {
            reject(event.target.errorCode)
        }
        request.onsuccess = (event) => {
            resolve(event.target.result)
        }
        request.onupgradeneeded = (event) => {
            const db = event.target.result
            db.createObjectStore('kv', {keyPath: 'key'})
            resolve(db)
        }
    })
    return this._kvstore
}

TaDaDaJSKV.prototype.get = function (name) {
    return new Promise((resolve, reject) => {
        this._initKVStore()
        .then(db => {
            const req = db.transaction(['kv'])
                .objectStore('kv')
                .get(name)
            req.onerror = (event) => {
                reject(event.target.errorCode)
            }
            req.onsuccess = (event) => {
                if (!event.target.result) { return resolve('')}
                resolve(event.target.result.value)
            }
        })
        .catch(e => {
            reject(new Error('Database error', {cause: e}))
        })
    })
}

TaDaDaJSKV.prototype.set = function (name, value) {
    return new Promise((resolve, reject) => {
        this._initKVStore()
        .then(db => {
            const req = db.transaction(['kv'], 'readwrite')
                .objectStore('kv')
                .put({key: name, value: value})
            req.onerror = (event) => {
                reject(event.target.errorCode)
            }
            req.onsuccess = (event) => {
                resolve(event.target.result)
            }
        })
    })
}

TaDaDaJSKV.prototype.del = function (name) {
    return new Promise((resolve, reject) => {
        this._initKVStore()
        .then(db => {
            const req = db.transaction(['kv'], 'readwrite')
                .objectStore('kv')
                .delete(name)
            req.onerror = (event) => {
                reject(event.target.errorCode)
            }
            req.success = (event) => {
                resolve(event.target.result)
            }
        })
    })
}


function TaDaDaJS (path = '.auth', base = null) {
    if (TaDaDaJS._instance) { return TaDaDaJS._instance }
    this.path = path
    this.halgo = 'SHA-384'
    this.pbkdf2_iterations = [100000, 200000]
    this.base = base || window.location
    this.kvstore = new TaDaDaJSKV()
    TaDaDaJS.instance = this
}

TaDaDaJS.prototype.getAlgoLength = function (algo) {
    switch (algo) {
        default:
        case 'SHA-256': return 256
        case 'SHA-384': return 384
        case 'SHA-512': return 512
    }
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

TaDaDaJS.prototype.init = function (userid, nonce = null) {
    return new Promise((resolve, reject) => {
        const params = {userid: userid}
        if (nonce !== null) { params.cnonce = this.arrayToB64(nonce) }
        fetch (new URL(`${this.path}/init`, this.base), {method: 'POST', body: JSON.stringify({userid, cnonce: this.arrayToB64(nonce), hash: this.halgo})})
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
    return array
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
            salt: new Uint8Array(this.getAlgoLength(this.halgo) / 8),
            iterations: getRandomInt(this.pbkdf2_iterations[0], this.pbkdf2_iterations[1]),
            algo: this.halgo
        }
        crypto.getRandomValues(outKey.salt)
        crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
        .then(cryptokey => {
            return crypto.subtle.deriveKey({name: 'PBKDF2', hash: this.halgo, salt: outKey.salt, iterations: outKey.iterations}, 
                cryptokey, {name: 'HMAC', hash: this.halgo, length: this.getAlgoLength(this.halgo)}, true, ['sign'])
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

TaDaDaJS.prototype.setPassword = function (userid, password) {
    return new Promise((resolve, reject) => {
        this.genPassword(password)
        .then(key => {
            return fetch(new URL(`${this.path}/setpassword`, this.base), {method: 'POST', body:
                JSON.stringify({userid: userid, key: key.derived, salt: key.salt, iterations: key.iterations, algo: key.algo })})
        })
        .then(response => {
            return response.json()
        })
        .then(user => {
            resolve(user)
        })
        .catch(e => {
            reject(new Error('Password change failed', {cause: e}))
        })
    })
}

TaDaDaJS.prototype.genToken = function (params, password, nonce = null) {
    return new Promise ((resolve, reject) => {
        crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
        .then(cryptokey => {
            const salt = this.b64ToArray(params.salt).buffer
            return crypto.subtle.deriveKey({name: 'PBKDF2', hash: this.halgo, salt: salt, iterations: parseInt(params.count)}, 
                cryptokey, {name: 'HMAC', hash: this.halgo, length: this.getAlgoLength(this.halgo)}, false, ['sign'])
        })
        .then(key => {
            const auth = this.b64ToArray(params.auth)
            const sign = new Uint8Array(auth.length + (nonce === null ? 0 : nonce.length))
            sign.set(auth)
            if (nonce) { sign.set(nonce, auth.length) }
            return crypto.subtle.sign({name: 'HMAC', hash: this.halgo, length: this.getAlgoLength(this.halgo)}, key, sign)
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
    return this.kvstore.get('token')
}

TaDaDaJS.prototype.getUser = function () {
    return this.kvstore.get('userid')
}

TaDaDaJS.prototype.getCurrentUser = function () {
    return new Promise((resolve, reject) => {
        fetch (new URL(`${this.path}/whoami`, this.base), {method: 'POST', body: JSON.stringify({})})
        .then(response => {
            if (!response.ok) { return reject(new Error('login error')) }
            return response.json()
        })
        .then(result => {
            return resolve(result.userid)
        })
    })
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

TaDaDaJS.prototype.getShareType = function (name) {
    switch(name) {
        default:
        case 'share-limited': return [86400, false]
        case 'share-once-limited': return [600, true]
        case 'share-once-unlimited': return [-1, true]
        case 'share-unlimited': return [-1, false]
    }
}

TaDaDaJS.prototype.genUrl = function (url, params = {}, type = [86400, false]) {
    return new Promise((resolve, reject) => {
        if (!(url instanceof URL)) { url = new URL(url) }
        Object.keys(params).forEach(k => {
            url.searchParams.append(k, params[k])
        })
        this.getShareableToken(url, '', type[0], type[1])
        .then(token => {
            url.searchParams.append('access_token', token)
            resolve(url)
        })
        .catch(cause => {
            reject('Cannot get token', {cause : cause})
        })
    })
}

TaDaDaJS.prototype.getShareableToken = function (url, comment = '', duration = 86400, once = false) {
    return new Promise((resolve, reject) => {
        this.getToken()
        .then(token => {
            return fetch(new URL(`${this.path}/getshareable`, this.base), {method: 'POST', body: JSON.stringify({auth: token, url, comment, permanent: duration <= 0, duration, once, hash: this.halgo})})
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
        this.kvstore.get('token')
        .then(token => {
            this.quit(token)
            .finally(() => {
                this.kvstore.del('token')
                this.kvstore.del('userid')
                resolve()
            })
        })
    })
}

TaDaDaJS.prototype.getNonce = function () {
    const arr = new Uint8Array(this.getAlgoLength(this.halgo) / 8)
    crypto.getRandomValues(arr)
    return arr
}

TaDaDaJS.prototype.isLogged = function () {
    return new Promise((resolve, reject) => {
        this.kvstore.get('token')
        .then(token => {
            this.check(token)
            .then(token => {
                return resolve(token)
            })
            .catch(cause => {
                reject(new Error('Error login', {cause: cause}))
            })
        })
    })
}

/* a bit ugly ... */
TaDaDaJS.prototype.checkPassword = function (userid, password) {
    return new Promise(resolve => {
        const nonce = this.getNonce()
        this.init(userid, nonce)
        .then(params => {
            if (params.algo) {
                switch (params.algo) {
                    default:
                    case 'SHA-256': this.halgo = 'SHA-256'; break;
                    case 'SHA-384': this.halgo = 'SHA-384'; break;
                    case 'SHA-512': this.halgo = 'SHA-512'; break;
                }
            }
            return this.genToken(params, password, nonce)
        })
        .then(token => {
            this.check(token)
        })
        .then(token => {
            this.quit(token)
            resolve(true)
        })
        .catch(_ => {
            resolve(false)
        })
    })
}

TaDaDaJS.prototype.login = function (userid, password) {
    return new Promise((resolve, reject) => {
        const nonce = this.getNonce()
        this.init(userid, nonce)
        .then(params => {
            if (params.algo) {
                switch (params.algo) {
                    default:
                    case 'SHA-256': this.halgo = 'SHA-256'; break;
                    case 'SHA-384': this.halgo = 'SHA-384'; break;
                    case 'SHA-512': this.halgo = 'SHA-512'; break;
                }
            }
            return this.genToken(params, password, nonce)
        })
        .then(token => {
            return this.check(token)
        })
        .then(token => {
            Promise.all([this.kvstore.set('userid', userid),
                this.kvstore.set('token', token)])
            .then(_ => {
                resolve(token)
            })
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