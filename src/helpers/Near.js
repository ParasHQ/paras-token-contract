const { Contract, KeyPair, connect } = require('near-api-js')
const { join } = require('path')
const { InMemoryKeyStore } = require('near-api-js').keyStores
const getConfig = require('../configs/near')

const Base64 = require('js-base64').Base64
const nacl = require('tweetnacl')
const bs58 = require('bs58')
const sha256 = require('js-sha256')
const axios = require('axios')

const _hexToArr = (str) => {
	try {
		return new Uint8Array(
			str.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
		)
	} catch (err) {
		throw err
	}
}

const contractConfig = {
	changeMethods: [
		'new',
        'ft_transfer',
        'ft_transfer_call',
        'ft_resolve_transfer'
	],
    viewMethods: [
        'ft_total_supply',
        'ft_balance_of',
        'ft_metadata'    
    ]
}

class Near {
	constructor() {
		this.ctx = null
		this.config = null
	}

	async init() {
		console.log('==================================================')
		console.log(`ENV: ${process.env.NODE_ENV}`)
		const ROOT_ACCOUNT =
			process.env[`${process.env.NODE_ENV.toUpperCase()}_ROOT_ACCOUNT`]
		const CONTRACT_ACCOUNT =
			process.env[`${process.env.NODE_ENV.toUpperCase()}_CONTRACT_ACCOUNT`]

		if (!ROOT_ACCOUNT) {
			throw '[env] ROOT_ACCOUNT not found'
		}
		if (!CONTRACT_ACCOUNT) {
			throw '[env] CONTRACT_ACCOUNT not found'
		}
		const rootAccount = JSON.parse(ROOT_ACCOUNT)
		const contractAccount = JSON.parse(CONTRACT_ACCOUNT)
		console.log(`ROOT ACCOUNT: ${rootAccount.account_id}`)
		console.log(`CONTRACT ACCOUNT: ${contractAccount.account_id}`)
		console.log('==================================================')
		const config = getConfig(
			process.env.NODE_ENV || 'testnet',
			contractAccount.account_id
		)
		this.config = config

		const keyStore = new InMemoryKeyStore()

		// add root account
		const rootKeyPair = KeyPair.fromString(
			rootAccount.secret_key || rootAccount.private_key
		)
		await keyStore.setKey(config.networkId, rootAccount.account_id, rootKeyPair)

		// add contract account
		const contractKeyPair = KeyPair.fromString(
			contractAccount.secret_key || contractAccount.private_key
		)
		await keyStore.setKey(
			config.networkId,
			contractAccount.account_id,
			contractKeyPair
		)

		const near = await connect({
			deps: {
				keyStore: keyStore,
			},
			...config,
		})
		this.ctx = near
		this.masterAccount = await near.account(rootAccount.account_id)
		this.contractAccount = await near.account(contractAccount.account_id)
		this.contract = new Contract(
			this.masterAccount,
			this.contractAccount.accountId,
			contractConfig
		)
	}

	async deployContract() {
		console.log('Setting up and deploying contract')
		const contractPath = join(process.cwd(), 'res/fungible_token.wasm')
		await this.contractAccount.deployContract(
			require('fs').readFileSync(contractPath)
		)

		console.log(`Contract ${this.contractAccount.accountId} deployed`)
	}

	async initContract() {
		console.log(`ENV: ${process.env.NODE_ENV}`)
		const OWNER_ID = process.env[`${process.env.NODE_ENV.toUpperCase()}_OWNER_ID`]
		const TOTAL_SUPPLY = process.env[`${process.env.NODE_ENV.toUpperCase()}_TOTAL_SUPPLY`]
		const METADATA_TOKEN_NAME = process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_NAME`]
		const METADATA_TOKEN_SYMBOL = process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_SYMBOL`]
		const METADATA_TOKEN_ICON = process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_ICON`]
		const METADATA_TOKEN_DECIMALS = Number(process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_DECIMALS`])
		const METADATA_TOKEN_REFERENCE = process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_REFERENCE`]
		const METADATA_TOKEN_REFERENCE_HASH = process.env[`${process.env.NODE_ENV.toUpperCase()}_METADATA_TOKEN_REFERENCE_HASH`]
		console.log(`OWNER_ID: ${OWNER_ID}`)
		console.log(`TOTAL_SUPPLY: ${TOTAL_SUPPLY}`)
		console.log(`METADATA_TOKEN_NAME: ${METADATA_TOKEN_NAME}`)
		console.log(`METADATA_TOKEN_SYMBOL: ${METADATA_TOKEN_SYMBOL}`)
		console.log(`METADATA_TOKEN_DECIMALS: ${METADATA_TOKEN_DECIMALS}`)
		console.log(`METADATA_TOKEN_REFERENCE: ${METADATA_TOKEN_REFERENCE}`)
		console.log(`METADATA_TOKEN_REFERENCE_HASH: ${METADATA_TOKEN_REFERENCE_HASH}`)

		console.log('Initialize fungible token contract')
		this.contractAccount.functionCall(this.contractAccount.accountId, "new", {
			"owner_id": OWNER_ID,
			"total_supply": TOTAL_SUPPLY,
			"metadata": {
				"spec": "ft-1.0.0",
				"name": METADATA_TOKEN_NAME,
				"symbol": METADATA_TOKEN_SYMBOL,
				"icon": METADATA_TOKEN_ICON,
				"reference": undefined,
				"reference_hash": undefined,
				"decimals": METADATA_TOKEN_DECIMALS
			}
		})
	}

	async authSignature(authHeader) {
		try {
			const decodeAuthHeader = Base64.decode(authHeader)
			const [userId, pubKey, signature] = decodeAuthHeader.split('&')
			const pubKeyArr = _hexToArr(pubKey)
			const signatureArr = _hexToArr(signature)
			const hash = new Uint8Array(sha256.sha256.array(userId))
			const verify = nacl.sign.detached.verify(hash, signatureArr, pubKeyArr)
			if (!verify) {
				throw new Error('unauthorized')
			}
			const b58pubKey = bs58.encode(Buffer.from(pubKey.toUpperCase(), 'hex'))
			const response = await axios.post(this.config.nodeUrl, {
				jsonrpc: '2.0',
				id: 'dontcare',
				method: 'query',
				params: {
					request_type: 'view_access_key',
					finality: 'final',
					account_id: userId,
					public_key: `ed25519:${b58pubKey}`,
				},
			})

			if (response.data.result && response.data.result.error) {
				console.log(response.data.result.error)
				throw new Error('unauthorized')
			}
			return userId
		} catch (err) {
			return null
		}
	}
}

module.exports = Near
