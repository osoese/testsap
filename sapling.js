/**
 * (c) 2020 ieatpizza
 */
(function( Sapling, $, undefined ) {
	const params = {
		mod_q : 52435875175126190479447740508185965837690552500527637822603658699938581184513n,
		jj_d : 19257038036680949359750312669786877991949435402254120286184196891950884077233n,
		base : [[4139425550610461525665941076812662132363359224232624900223172373014329534291n,
				 39635691377166599497441725607757882405510648532010642268690928210480481875248n],
				[9201111513613159952332790701602097324772839388200533360387436201225747309937n,
				38317288103109448611012419043659719984035489099661802521426844652233060903143n]],
		mod_r : 6554484396890773809930967563523245729705921265872317281365359162392183254199n,
		ivk_twk : 2n**251n };
	function calcMod(x, mod = 'mod_q'){
		return ((x % params[mod]) + params[mod]) % params[mod];
	}
	function sapling_key_convert(key, isprivate = true){
		var keys = [key.slice(0, 32), key.slice(32, 64)];
		var result = [[], []];
		var mod_q_bin = (params['mod_q'] - 2n).toString(2).padStart(256, '0');
		for(var i = 0; i < keys.length; i++){
			if(isprivate){
				var key_bin = calcMod(BigInt('0x'+keys[i].reverse().map( str => Number(str).toString(16).padStart(2, '0')).join('')), 'mod_r').toString(2).padStart(256, '0');
				var ret = [0n, 1n];
				for(jj = 0; jj < key_bin.length; jj++){
					for(j = 0; j <= key_bin[jj]; j++){
						uv2 = ret;
						if(j == 1) uv2 = params['base'][i];
						x = calcMod(ret[1] * uv2[1]);
						var y = calcMod(params['jj_d'] * calcMod(ret[0] * calcMod(uv2[0] * x)));
						var uv = [1n, 1n];
						for(ii = 0; ii < mod_q_bin.length; ii++){
							uv[0] = calcMod(uv[0] ** 2n);
							uv[1] = calcMod(uv[1] ** 2n);
							if(mod_q_bin[ii] == '1'){
								uv[0] = calcMod(uv[0] * calcMod(1n + y));
								uv[1] = calcMod(uv[1] * calcMod(1n - y));
							}
						}
						uv[0] = calcMod((calcMod((calcMod(ret[0] * uv2[1])) + (calcMod(ret[1] * uv2[0])))) * uv[0]);
						ret[1] = calcMod((calcMod(x - (calcMod(-1n * (calcMod(ret[0] * uv2[0])))))) * uv[1]);
						ret[0] = uv[0];
					}
				}
				buf = ret[1].toString(16).padStart(64, '0').match(/.{1,2}/g).map( str => parseInt(str, 16) );
				if(ret[0] % 2n == 1n)
					buf[0] = buf[0] | 0x80;
				result[i] = buf.reverse();
			}else
				result[i] = keys[i];
		}
		var blake = BigInt('0x'+new BLAKE2s(32,{personalization:(new TextEncoder("utf-8").encode("Zcashivk"))}).update(result[0]).update(result[1]).hexDigest().match(/.{1,2}/g).reverse().join(''));
		return result.concat([i2leosp(calcMod(calcMod(blake, 'ivk_twk'), 'mod_r'), 256) ]);
	}
	Sapling.deriveMaster = function (seed, mode = 'main'){
		if(seed.length % 2 != 0 || seed.length < 64) return false;
		var result = [];
		while (seed.length >= 2) {
			result.push(parseInt(seed.substring(0, 2), 16));
			seed = seed.substring(2, seed.length);
		}
		seed_fingerprint = new BLAKE2b(32,{personalization:(new TextEncoder("utf-8").encode("Zcash_HD_Seed_FP"))}).update(result).digest();
		hash = new BLAKE2b(64,{personalization:(new TextEncoder("utf-8").encode("ZcashIP32Sapling"))}).update(result).digest();
		d_ask = toScalar(expand(hash.subarray(0, 32), 0x00));
		d_nsk = toScalar(expand(hash.subarray(0, 32), 0x01));
		d_ovk = truncate(expand(hash.subarray(0, 32), 0x02));
		d_dk = truncate(expand(hash.subarray(0, 32), 0x10));
		chain_c = hash.subarray(32, 64);

		//0 depth, 0 parent tag, 0 i
		encode = [0, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0].concat(...chain_c, i2leosp(d_ask, 256), i2leosp(d_nsk, 256), ...d_ovk, ...d_dk);
		bech32 = Bech32.encode('secret-extended-key-' + mode, Bech32.toWords(encode), 305);
		return { ask: d_ask, nsk: d_nsk, ovk: d_ovk, dk: d_dk, chainCode: chain_c,
				seed_fingerprint: seed_fingerprint, encode: encode, bech32: bech32 }
	}
	Sapling.deriveChild = function (i, harden = false){
		i = i & 0x7FFFFFFF;
		if(harden) i = (i | 0x80000000)  >>> 0;
		var isPrivate = this.zip32_isPrivate;
		var p_ask = (this.zip32_decoded.ask);
		var p_nsk = (this.zip32_decoded.nsk);

		var getaknk = this.zip32_aknk;

		var parentFvk = new BLAKE2b(32,{personalization:(new TextEncoder("utf-8").encode("ZcashSaplingFVFP"))}).update(getaknk[0]).update(getaknk[1]).update(this.zip32_decoded.ovk).digest();
		mode = this.zip32_network;
		depth = leos2ip_int(this.zip32_decoded.depth);


		if(i >= 0x80000000 && !isPrivate) return false;
		if(i >= 0x80000000) prfPrefix = [0x11].concat(p_ask, p_nsk);
		else{
			if(!isPrivate) prfPrefix = [0x12].concat(p_ask, p_nsk);
			else{

				prfPrefix = [0x12].concat(getaknk[0], getaknk[1]);
			}
		}

		hash = expand(this.zip32_decoded.chainCode, prfPrefix.concat(this.zip32_decoded.key_parts, i2leosp(i, 32)));
		spendkey = hash.subarray(0, 32);
		chaincode = hash.subarray(32, 64);

		var i_ask = toScalar(expand(spendkey, 0x13));
		var i_nsk = toScalar(expand(spendkey, 0x14));

		if(!isPrivate){
			aknk = sapling_key_convert(i2leosp(i_ask, 256).concat(i2leosp(i_nsk, 256)), true);
			i_ask = toScalar(aknk[0]);
			i_nsk = toScalar(aknk[1]);
			hrp = (mode == 'main') ? 'zxviews' : 'zxviewtestsapling';
		}
		else hrp = 'secret-extended-key-' + mode;
		//todo: public keys
		c_ask = i2leosp(calcMod(i_ask + toScalar(p_ask), 'mod_r'), 256);
		c_nsk = i2leosp(calcMod(i_nsk + toScalar(p_nsk), 'mod_r'), 256);
		c_ovk = truncate(expand(spendkey, [0x15].concat(this.zip32_decoded.ovk)), 32);
		c_dk = truncate(expand(spendkey, [0x16].concat(this.zip32_decoded.dk)), 32);

		encode = i2leosp((depth + 1) & 0xff, 8).concat(...truncate(parentFvk, 4), i2leosp(i, 32), ...chaincode, c_ask, c_nsk, ...c_ovk, ...c_dk);
		bech32 = Bech32.encode(hrp, Bech32.toWords(encode), 305);

		if(isPrivate)
			return { ask: c_ask, nsk: c_nsk, ovk: c_ovk, dk: c_dk, chainCode: chaincode, encode: encode, bech32: bech32, fvk: parentFvk }
		else
			return { ak: c_ask, nk: c_nsk, ovk: c_ovk, dk: c_dk, chainCode: chaincode, encode: encode, bech32: bech32, fvk: parentFvk }
	}
	function expand(sk, t){
		return new BLAKE2b(64,{personalization:(new TextEncoder("utf-8").encode("Zcash_ExpandSeed"))}).update(sk).update(t).digest();
	}
	function truncate(a, s=32){
		return a.subarray(0, s);
	}
	function toScalar(a){
		return calcMod(leos2ip(a), 'mod_r');
	}
	function leos2ip(a){
		return BigInt('0x' + a.map( str => ('0' + (str & 0xFF).toString(16)).slice(-2) ).reverse().join(''));
	}
	function leos2ip_int(a){
		return parseInt(a.map( str => ('0' + (str & 0xFF).toString(16)).slice(-2) ).reverse().join(''), 16);
	}
	function i2leosp(i, x = 512){
		return i.toString(16).padStart(2 * x/8, '0').match(/.{1,2}/g).reverse().map( str => parseInt(str, 16) );
	}
	Sapling.encode = function (str){
		try{
			var decoded = Bech32.decode(str, 305);
			address = Bech32.fromWords(decoded['words']);
			type = (decoded['prefix'].includes('test')) ? 'testsapling' : 's';
			if(address.length == 169){
				ivkconv = sapling_key_convert(address.slice(41, 41+64), decoded['prefix'].includes('secret'));
				header = address.slice(0, 41);
				aknkovk = ivkconv[0].concat(ivkconv[1], address.slice(105, 105+32));
				dk = address.slice(137, 137+32);

				this.zip32_decoded = { raw: address, depth: address.slice(0, 1), fvk_tag: address.slice(1, 5), index: address.slice(5, 9), chainCode: address.slice(9, 41), ask: address.slice(41, 73), nsk: address.slice(73, 105), ovk: address.slice(105, 137), dk: address.slice(137, 169), key_parts: address.slice(105, 169) };
				this.zip32_network = (type == 'testsapling') ? 'test' : 'main';
				this.zip32_isPrivate = decoded['prefix'].includes('secret');
				this.zip32_aknk = ivkconv;
			}else if(address.length == 96 && decoded['prefix'].includes('zview')){
				ivkconv = sapling_key_convert(address.slice(0, 64), false);
				aknkovk = ivkconv[0].concat(ivkconv[1], address.slice(64, 64+32));
			}else return 'Not supported input type. Key should be a valid key of one of these prefixes: secret-extended-key-(main/test), zxview(s/testsapling), zview(s/testsapling)';
			out = { 'inkey': str,
				'key_type': this.zip32_network,
				'ivk': Bech32.encode('zivk' + type, Bech32.toWords(ivkconv[2], 74)),
				'view': Bech32.encode('zview' + type, Bech32.toWords(aknkovk), 177)};
			if(dk){
				out['ivkdk'] = Bech32.encode('zivk' + type + 'dk', Bech32.toWords(ivkconv[2].concat(dk)), 127);
				out['xview'] = Bech32.encode('zxview' + type, Bech32.toWords(header.concat(aknkovk, dk)), 295);
				out['depth'] = leos2ip_int(this.zip32_decoded.depth);
				index = leos2ip_int(this.zip32_decoded.index);
				if(index >= 0x80000000) index = (index & 0x7FFFFFFF).toString() + ' (hardened)';
				out['index'] = index;
				out['fvk_tag'] = Array.from(this.zip32_decoded.fvk_tag, function(byte) { return ('0' + (byte & 0xFF).toString(16)).slice(-2); }).join('');
				out['chaincode'] = Array.from(this.zip32_decoded.chainCode, function(byte) { return ('0' + (byte & 0xFF).toString(16)).slice(-2); }).join('');
			}
			return out;
		}catch(err){
			return err.message;
		}
	}
}( window.Sapling = window.Sapling || {} ));
