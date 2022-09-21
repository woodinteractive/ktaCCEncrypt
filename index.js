const pidCrypt = require('pidcrypt')
const pidCryptUtil = require('pidcrypt/pidcrypt_util')
require('pidcrypt/rsa')
require('pidcrypt/asn1')

let public_key =
	'-----BEGIN RSA PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0QmKXJTE0G7aO2j32Pui\n\
xgiNDyAoprnLbihUxl0mnPQHoxFNeiHB0eUEjcRvShTYbzFOYa78mTpYgx0ztvwo\n\
gAwBWEmn2QMKuqXOEOdb9HeOl63MWqAaEK1yNheWj5fDZNXnsSsya4lL7JTG1dCd\n\
uek6g4uUcrgXBEXifOXyT5Z7Gb202nPhclOXMwZIstGpygkXEpN+n4JTkEA9b1Fk\n\
37aiLes4H5AaahgqbOM7ytjOzaWthwJDtVMPvK0ZYDi1JWAOXxjXTRA4OKeXC8j3\n\
29u09v5BZ5LlTAWI0fNetRy9vIVG1Em545IHSzgrk0h7I09FV1N4Fv9PkCHTdlde\n\
3wIDAQAB\n\
-----END RSA PUBLIC KEY-----'

function isNumber(n) {
	return !isNaN(parseFloat(n)) && isFinite(n)
}

function IETrim(input) {
	return input.replace(/\s/g, '')
}

function certParser(cert) {
	let lines = cert.split('\n')
	let read = false
	let b64 = false
	let end = false
	let flag = ''
	let retObj = {}
	retObj.info = ''
	retObj.salt = ''
	retObj.iv
	retObj.b64 = ''
	retObj.aes = false
	retObj.mode = ''
	retObj.bits = 0
	for (let i = 0; i < lines.length; i++) {
		flag = lines[i].substr(0, 9)
		if (i == 1 && flag != 'Proc-Type' && flag.indexOf('M') == 0)
			//unencrypted cert?
			b64 = true
		switch (flag) {
			case '-----BEGI':
				read = true
				break
			case 'Proc-Type':
				if (read) retObj.info = lines[i]
				break
			case 'DEK-Info:':
				if (read) {
					let tmp = lines[i].split(',')
					let dek = tmp[0].split(': ')
					let aes = dek[1].split('-')
					retObj.aes = aes[0] == 'AES' ? true : false
					retObj.mode = aes[2]
					retObj.bits = parseInt(aes[1])
					retObj.salt = tmp[1].substr(0, 16)
					retObj.iv = tmp[1]
				}
				break
			case '':
				if (read) b64 = true
				break
			case '-----END ':
				if (read) {
					b64 = false
					read = false
				}
				break
			default:
				if (read && b64) retObj.b64 += pidCryptUtil.stripLineFeeds(lines[i])
		}
	}
	return retObj
}

const BuildXML = (PAN, ExpDate, CVV) => {
	PAN = IETrim(PAN)
	ExpDate = IETrim(ExpDate)
	CVV = IETrim(CVV)
	// validation
	if (PAN == '') {
		return 'Account Number blank'
	}
	if (ExpDate == '') {
		return 'Expiration Date blank'
	}
	if (CVV == '') {
		return 'CVV blank'
	}
	if (!isNumber(PAN)) {
		return 'Account Number non-Numeric'
	}

	let params = {}
	params = certParser(public_key)
	if (params.b64) {
		let key = pidCryptUtil.decodeBase64(params.b64)
		let rsa = new pidCrypt.RSA()
		let asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key))
		let tree = asn.toHexTree()
		rsa.setPublicKeyFromASN(tree)

		let xmlstring
		let KSN = 'TEMPUSRSA2014'
		let EncType = 'RSA'
		let OAEPAdded = 'FALSE'
		let CardDataSource = 'KEY'

		let EncryptedPAN = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(rsa.encryptRaw(PAN))), 64))
		let EncryptedExpDate = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(rsa.encryptRaw(ExpDate))), 64))
		let EncryptedCVV = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(rsa.encryptRaw(CVV))), 64))

		xmlstring = '<CARDEVENTPARAMS>'
		xmlstring = xmlstring + '<ENCDVCDEVICETYPE>' + '6' + '</ENCDVCDEVICETYPE>'
		xmlstring = xmlstring + '<ENCDVCKSN>' + KSN + '</ENCDVCKSN>'
		xmlstring = xmlstring + '<ENCDVCENCTYPE>' + EncType + '</ENCDVCENCTYPE>'
		xmlstring = xmlstring + '<ENCDVCENCOAEPPADDED>' + OAEPAdded + '</ENCDVCENCOAEPPADDED>'
		xmlstring = xmlstring + '<ENCDVCCARDDATASOURCE>' + CardDataSource + '</ENCDVCCARDDATASOURCE>'
		xmlstring = xmlstring + '<ENCDVCENCRYPTEDPAN>' + EncryptedPAN + '</ENCDVCENCRYPTEDPAN>'
		xmlstring = xmlstring + '<ENCDVCENCRYPTEDEXP>' + EncryptedExpDate + '</ENCDVCENCRYPTEDEXP>'
		xmlstring = xmlstring + '<ENCDVCENCRYPTEDCVV>' + EncryptedCVV + '</ENCDVCENCRYPTEDCVV>'
		xmlstring = xmlstring + '</CARDEVENTPARAMS>'

		return xmlstring
	} else {
		return 'No Public Key Found'
	}
}

module.exports = BuildXML
