var BLAKE2b = (function() {
    var BLOCK_SIZE = 128;
    var DIGEST_LENGTH = 64;
    var KEY_LENGTH = 64;
    var PERSONALIZATION_LENGTH = 16;
    var SALT_LENGTH = 16;

    var MAX_LEAF_SIZE = Math.pow(2, 32) - 1;
    var MAX_FANOUT = 255;
    var MAX_MAX_DEPTH = 255; // not a typo

    function readUint32LE(array, offset = 0) {
        return ((array[offset + 3] << 24) |
            (array[offset + 2] << 16) |
            (array[offset + 1] << 8) |
            array[offset]) >>> 0;
    }

    function writeUint32LE(value, out, offset = 0) {
        out[offset + 0] = value >>> 0;
        out[offset + 1] = value >>> 8;
        out[offset + 2] = value >>> 16;
        out[offset + 3] = value >>> 24;
        return out;
    }

    var IV = new Uint32Array([
        0xf3bcc908, 0x6a09e667,
        0x84caa73b, 0xbb67ae85,
        0xfe94f82b, 0x3c6ef372,
        0x5f1d36f1, 0xa54ff53a,
        0xade682d1, 0x510e527f,
        0x2b3e6c1f, 0x9b05688c,
        0xfb41bd6b, 0x1f83d9ab,
        0x137e2179, 0x5be0cd19,
    ]);

    var SIGMA = [
        [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
        [28, 20, 8, 16, 18, 30, 26, 12, 2, 24, 0, 4, 22, 14, 10, 6],
        [22, 16, 24, 0, 10, 4, 30, 26, 20, 28, 6, 12, 14, 2, 18, 8],
        [14, 18, 6, 2, 26, 24, 22, 28, 4, 12, 10, 20, 8, 0, 30, 16],
        [18, 0, 10, 14, 4, 8, 20, 30, 28, 2, 22, 24, 12, 16, 6, 26],
        [4, 24, 12, 20, 0, 22, 16, 6, 8, 26, 14, 10, 30, 28, 2, 18],
        [24, 10, 2, 30, 28, 26, 8, 20, 0, 14, 12, 6, 18, 4, 16, 22],
        [26, 22, 14, 28, 24, 2, 6, 18, 10, 0, 30, 8, 16, 12, 4, 20],
        [12, 30, 28, 18, 22, 6, 0, 16, 24, 4, 26, 14, 2, 8, 20, 10],
        [20, 4, 16, 8, 14, 12, 2, 10, 30, 22, 18, 28, 6, 24, 26, 0],
        [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
        [28, 20, 8, 16, 18, 30, 26, 12, 2, 24, 0, 4, 22, 14, 10, 6]
    ];

    function BLAKE2b(digestLength, config) {
        this._bufferLength = 0;
        this._lastNode = false;
        this._finished = false;
        this._paddedKey = undefined;
        this._state = new Int32Array(IV);
        this._buffer = new Uint8Array(BLOCK_SIZE);
        this._ctr = new Uint32Array(4);
        this._flag = new Uint32Array(4);
        this._vtmp = new Uint32Array(32);
        this._mtmp = new Uint32Array(32);
        this._paddedKey = undefined;
        // Validate digest length.
        if (digestLength < 1 || digestLength > DIGEST_LENGTH) {
            throw new Error("blake2b: wrong digest length");
        }
        this.digestLength = digestLength;

        // Validate config, if present.
        if (config) {
            validateConfig(config);
        }

        // Get key length from config.
        let keyLength = 0;
        if (config && config.key) {
            keyLength = config.key.length;
        }

        // Get tree fanout and maxDepth from config.
        let fanout = 1;
        let maxDepth = 1;
        if (config && config.tree) {
            fanout = config.tree.fanout;
            maxDepth = config.tree.maxDepth;
        }

        // Xor common parameters into state.
        this._state[0] ^= digestLength | (keyLength << 8) | (fanout << 16) | (maxDepth << 24);

        // Xor tree parameters into state.
        if (config && config.tree) {
            this._state[1] ^= config.tree.leafSize;

            this._state[2] ^= config.tree.nodeOffsetLowBits;
            this._state[3] ^= config.tree.nodeOffsetHighBits;
            this._state[4] ^= config.tree.nodeDepth | (config.tree.innerDigestLength << 8);

            this._lastNode = config.tree.lastNode;
        }

        // Xor salt into state.
        if (config && config.salt) {
            this._state[8] ^= readUint32LE(config.salt, 0);
            this._state[9] ^= readUint32LE(config.salt, 4);
            this._state[10] ^= readUint32LE(config.salt, 8);
            this._state[11] ^= readUint32LE(config.salt, 12);
        }

        // Xor personalization into state.
        if (config && config.personalization) {
            this._state[12] ^= readUint32LE(config.personalization, 0);
            this._state[13] ^= readUint32LE(config.personalization, 4);
            this._state[14] ^= readUint32LE(config.personalization, 8);
            this._state[15] ^= readUint32LE(config.personalization, 12);
        }

        // Process key.
        if (config && config.key && keyLength > 0) {
            this._paddedKey = new Uint8Array(BLOCK_SIZE);
            this._paddedKey.set(config.key);

            // Put padded key into buffer.
            this._buffer.set(this._paddedKey);
            this._bufferLength = BLOCK_SIZE;
        }
    }

    function validateConfig(config) {
        if (config.key && config.key.length > KEY_LENGTH) {
            throw new Error("blake2b: wrong key length");
        }
        if (config.salt && config.salt.length !== SALT_LENGTH) {
            throw new Error("blake2b: wrong salt length");
        }
        if (config.personalization &&
            config.personalization.length !== PERSONALIZATION_LENGTH) {
            throw new Error("blake2b: wrong personalization length");
        }
        if (config.tree) {
            if (config.tree.fanout < 0 || config.tree.fanout > MAX_FANOUT) {
                throw new Error("blake2b: wrong tree fanout");
            }
            if (config.tree.maxDepth < 0 || config.tree.maxDepth > MAX_MAX_DEPTH) {
                throw new Error("blake2b: wrong tree depth");
            }
            if (config.tree.leafSize < 0 || config.tree.leafSize > MAX_LEAF_SIZE) {
                throw new Error("blake2b: wrong leaf size");
            }
            if (config.tree.innerDigestLength < 0 ||
                config.tree.innerDigestLength > DIGEST_LENGTH) {
                throw new Error("blake2b: wrong tree inner digest length");
            }
        }
    }

    BLAKE2b.prototype.update = function(data) {
        if (this._finished) {
            throw new Error("blake2b: can't update because hash was finished.");
        }

        var left = BLOCK_SIZE - this._bufferLength;
        let dataPos = 0;
        dataLength = data.length;

        if (dataLength === 0) {
            return this;
        }

        // Finish buffer.
        if (dataLength > left) {
            for (let i = 0; i < left; i++) {
                this._buffer[this._bufferLength + i] = data[dataPos + i];
            }
            this._processBlock(BLOCK_SIZE);
            dataPos += left;
            dataLength -= left;
            this._bufferLength = 0;
        }

        // Process data blocks.
        while (dataLength > BLOCK_SIZE) {
            for (let i = 0; i < BLOCK_SIZE; i++) {
                this._buffer[i] = data[dataPos + i];
            }
            this._processBlock(BLOCK_SIZE);
            dataPos += BLOCK_SIZE;
            dataLength -= BLOCK_SIZE;
            this._bufferLength = 0;
        }

        // Copy leftovers to buffer.
        for (let i = 0; i < dataLength; i++) {
            this._buffer[this._bufferLength + i] = data[dataPos + i];
        }
        this._bufferLength += dataLength;

        return this;
    }

    BLAKE2b.prototype.digest = function() {
        if (!this._finished) {
            for (let i = this._bufferLength; i < BLOCK_SIZE; i++) {
                this._buffer[i] = 0;
            }

            // Set last block flag.
            this._flag[0] = 0xffffffff;
            this._flag[1] = 0xffffffff;

            // Set last node flag if last node in tree.
            if (this._lastNode) {
                this._flag[2] = 0xffffffff;
                this._flag[3] = 0xffffffff;
            }

            this._processBlock(this._bufferLength);
            this._finished = true;
        }
        // Reuse buffer as temporary space for digest.
        var tmp = this._buffer.subarray(0, 64);
        for (let i = 0; i < 16; i++) {
            writeUint32LE(this._state[i], tmp, i * 4);
        }

        return tmp.subarray(0, this.digestLength);
    }


    function _G(v, al, bl, cl, dl, ah, bh, ch, dh, ml0, mh0, ml1, mh1) {
        let vla = v[al],
            vha = v[ah],
            vlb = v[bl],
            vhb = v[bh],
            vlc = v[cl],
            vhc = v[ch],
            vld = v[dl],
            vhd = v[dh];

        // 64-bit: va += vb
        let w = vla & 0xffff,
            x = vla >>> 16,
            y = vha & 0xffff,
            z = vha >>> 16;

        w += vlb & 0xffff;
        x += vlb >>> 16;
        y += vhb & 0xffff;
        z += vhb >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vha = (y & 0xffff) | (z << 16);
        vla = (w & 0xffff) | (x << 16);

        // 64-bit: va += m[sigma[r][2 * i + 0]]
        w = vla & 0xffff;
        x = vla >>> 16;
        y = vha & 0xffff;
        z = vha >>> 16;

        w += ml0 & 0xffff;
        x += ml0 >>> 16;
        y += mh0 & 0xffff;
        z += mh0 >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vha = (y & 0xffff) | (z << 16);
        vla = (w & 0xffff) | (x << 16);

        // 64-bit: vd ^= va
        vld ^= vla;
        vhd ^= vha;

        // 64-bit: rot(vd, 32)
        w = vhd;
        vhd = vld;
        vld = w;

        // 64-bit: vc += vd
        w = vlc & 0xffff;
        x = vlc >>> 16;
        y = vhc & 0xffff;
        z = vhc >>> 16;

        w += vld & 0xffff;
        x += vld >>> 16;
        y += vhd & 0xffff;
        z += vhd >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vhc = (y & 0xffff) | (z << 16);
        vlc = (w & 0xffff) | (x << 16);

        // 64-bit: vb ^= vc
        vlb ^= vlc;
        vhb ^= vhc;

        // 64-bit: rot(vb, 24)
        w = vlb << 8 | vhb >>> 24;
        vlb = vhb << 8 | vlb >>> 24;
        vhb = w;

        // 64-bit: va += vb
        w = vla & 0xffff;
        x = vla >>> 16;
        y = vha & 0xffff;
        z = vha >>> 16;

        w += vlb & 0xffff;
        x += vlb >>> 16;
        y += vhb & 0xffff;
        z += vhb >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vha = (y & 0xffff) | (z << 16);
        vla = (w & 0xffff) | (x << 16);

        // 64-bit: va += m[sigma[r][2 * i + 1]
        w = vla & 0xffff;
        x = vla >>> 16;
        y = vha & 0xffff;
        z = vha >>> 16;

        w += ml1 & 0xffff;
        x += ml1 >>> 16;
        y += mh1 & 0xffff;
        z += mh1 >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vha = (y & 0xffff) | (z << 16);
        vla = (w & 0xffff) | (x << 16);

        // 64-bit: vd ^= va
        vld ^= vla;
        vhd ^= vha;

        // 64-bit: rot(vd, 16)
        w = vld << 16 | vhd >>> 16;
        vld = vhd << 16 | vld >>> 16;
        vhd = w;

        // 64-bit: vc += vd
        w = vlc & 0xffff;
        x = vlc >>> 16;
        y = vhc & 0xffff;
        z = vhc >>> 16;

        w += vld & 0xffff;
        x += vld >>> 16;
        y += vhd & 0xffff;
        z += vhd >>> 16;

        x += w >>> 16;
        y += x >>> 16;
        z += y >>> 16;

        vhc = (y & 0xffff) | (z << 16);
        vlc = (w & 0xffff) | (x << 16);

        // 64-bit: vb ^= vc
        vlb ^= vlc;
        vhb ^= vhc;

        // 64-bit: rot(vb, 63)
        w = vhb << 1 | vlb >>> 31;
        vlb = vlb << 1 | vhb >>> 31;
        vhb = w;

        v[al] = vla;
        v[ah] = vha;
        v[bl] = vlb;
        v[bh] = vhb;
        v[cl] = vlc;
        v[ch] = vhc;
        v[dl] = vld;
        v[dh] = vhd;
    }

    BLAKE2b.prototype._processBlock = function(length) {
        for (let i = 0; i < 3; i++) {
            let a = this._ctr[i] + length;
            this._ctr[i] = a >>> 0;
            if (this._ctr[i] === a) {
                break;
            }
            length = 1;
        }
        let v = this._vtmp;
        v.set(this._state);
        v.set(IV, 16);
        v[12 * 2 + 0] ^= this._ctr[0];
        v[12 * 2 + 1] ^= this._ctr[1];
        v[13 * 2 + 0] ^= this._ctr[2];
        v[13 * 2 + 1] ^= this._ctr[3];
        v[14 * 2 + 0] ^= this._flag[0];
        v[14 * 2 + 1] ^= this._flag[1];
        v[15 * 2 + 0] ^= this._flag[2];
        v[15 * 2 + 1] ^= this._flag[3];

        let m = this._mtmp;
        for (let i = 0; i < 32; i++) {
            m[i] = readUint32LE(this._buffer, i * 4);
        }

        for (let r = 0; r < 12; r++) {
            _G(v,
                0, 8, 16, 24,
                1, 9, 17, 25,
                m[SIGMA[r][0]], m[SIGMA[r][0] + 1],
                m[SIGMA[r][1]], m[SIGMA[r][1] + 1]
            );

            _G(v,
                2, 10, 18, 26,
                3, 11, 19, 27,
                m[SIGMA[r][2]], m[SIGMA[r][2] + 1],
                m[SIGMA[r][3]], m[SIGMA[r][3] + 1]
            );

            _G(v,
                4, 12, 20, 28,
                5, 13, 21, 29,
                m[SIGMA[r][4]], m[SIGMA[r][4] + 1],
                m[SIGMA[r][5]], m[SIGMA[r][5] + 1]
            );

            _G(v,
                6, 14, 22, 30,
                7, 15, 23, 31,
                m[SIGMA[r][6]], m[SIGMA[r][6] + 1],
                m[SIGMA[r][7]], m[SIGMA[r][7] + 1]
            );

            _G(v,
                0, 10, 20, 30,
                1, 11, 21, 31,
                m[SIGMA[r][8]], m[SIGMA[r][8] + 1],
                m[SIGMA[r][9]], m[SIGMA[r][9] + 1]
            );

            _G(v,
                2, 12, 22, 24,
                3, 13, 23, 25,
                m[SIGMA[r][10]], m[SIGMA[r][10] + 1],
                m[SIGMA[r][11]], m[SIGMA[r][11] + 1]
            );

            _G(v,
                4, 14, 16, 26,
                5, 15, 17, 27,
                m[SIGMA[r][12]], m[SIGMA[r][12] + 1],
                m[SIGMA[r][13]], m[SIGMA[r][13] + 1]
            );

            _G(v,
                6, 8, 18, 28,
                7, 9, 19, 29,
                m[SIGMA[r][14]], m[SIGMA[r][14] + 1],
                m[SIGMA[r][15]], m[SIGMA[r][15] + 1]
            );
        }

        for (let i = 0; i < 16; i++) {
            this._state[i] ^= v[i] ^ v[i + 16];
        }
    }
    BLAKE2b.prototype.hexDigest = function() {
        var hex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
        var out = [];
        var d = this.digest();
        for (var i = 0; i < d.length; i++) {
            out.push(hex[(d[i] >> 4) & 0xf]);
            out.push(hex[d[i] & 0xf]);
        }
        return out.join('');
    };
    return BLAKE2b;

})();

if (typeof module !== 'undefined' && module.exports) module.exports = BLAKE2b;
