require('dotenv').config()
const Near = require('./src/helpers/Near')

const deploy = async () => {
	const near = new Near()

	await near.init()

	try {
		await near.initContract()
	} catch (err) {
		console.log(err)
	}
}

deploy()

