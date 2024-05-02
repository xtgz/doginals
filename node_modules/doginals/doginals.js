#!/usr/bin/env node

const dogecore = require('bitcore-lib-doge')
const axios = require('axios')
const fs = require('fs')
const dotenv = require('dotenv')
const mime = require('mime-types')
const express = require('express')
const { PrivateKey, Address, Transaction, Script, Opcode, HDPrivateKey } = dogecore
const { Hash, Signature } = dogecore.crypto
const {
    generateMnemonic: _generateMnemonic,
    mnemonicToSeed,
} = require('@scure/bip39');
const {
    wordlist,
} = require('@scure/bip39/wordlists/english');

function generateMnemonic(entropy = 256) {
    if (entropy !== 256 && entropy !== 128) {
        throw TypeError(
            `Incorrect entropy bits provided, expected 256 or 128 (24 or 12 word results), got: "${String(
        entropy
      )}".`
        );
    }
    return _generateMnemonic(wordlist, entropy);
}


if (fs.existsSync('.lock')) {
    throw new Error('Cannot acquire lock.');
}
fs.writeFileSync('.lock', 'locking');
const shutdown = () => {
    try {
        fs.unlinkSync('.lock');
    } catch (e) {

    }
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

dotenv.config()

if (process.env.TESTNET == 'true') {
    dogecore.Networks.defaultNetwork = dogecore.Networks.testnet
}

if (process.env.FEE_PER_KB) {
    Transaction.FEE_PER_KB = parseInt(process.env.FEE_PER_KB)
} else {
    Transaction.FEE_PER_KB = 100000
}
// Transaction.DUST_AMOUNT = 100000;

const NFT_DUST_AMOUNT = 0.3 * (10 ** 8);
// const NFT_DUST_AMOUNT = 100000;

const WALLET_PATH = process.env.WALLET || '.wallet.json'


async function main() {
    let cmd = process.argv[2]

    if (cmd == 'mint') {
        await mint()
    } else if (cmd == 'wallet') {
        await wallet()
    } else if (cmd == 'server') {
        await server()
    } else if (cmd == 'drc-20') {
        await doge20()   
    } else {
        throw new Error(`unknown command: ${cmd}`)
    }
}

async function doge20() {
  let subcmd = process.argv[3]

  if (subcmd === 'mint') {
    await doge20Transfer("mint")
  } else if (subcmd === 'transfer') {
    await doge20Transfer()
  } else if (subcmd === 'deploy') {
    await doge20Deploy()
  } else {
    throw new Error(`unknown subcommand: ${subcmd}`)
  }
}

async function doge20Deploy() {
  const argAddress = process.argv[4]
  const argTicker = process.argv[5]
  const argMax = process.argv[6]
  const argLimit = process.argv[7]

  const doge20Tx = {
    p: "drc-20",
    op: "deploy",
    tick: `${argTicker.toLowerCase()}`,
    max: `${argMax}`,
    lim: `${argLimit}`
  };

  const parsedDoge20Tx = JSON.stringify(doge20Tx);

  // encode the doge20Tx as hex string
  const encodedDoge20Tx = Buffer.from(parsedDoge20Tx).toString('hex');

  console.log("Deploying drc-20 token...");
  await mint(argAddress, "text/plain;charset=utf-8", encodedDoge20Tx);
}

async function doge20Transfer(op = "transfer") {
  const argAddress = process.argv[4]
  const argTicker = process.argv[5]
  const argAmount = process.argv[6]
  const argRepeat = Number(process.argv[7]) || 1;

  const doge20Tx = {
    p: "drc-20",
    op,
    tick: `${argTicker.toLowerCase()}`,
    amt: `${argAmount}`
  };

  const parsedDoge20Tx = JSON.stringify(doge20Tx);

  // encode the doge20Tx as hex string
  const encodedDoge20Tx = Buffer.from(parsedDoge20Tx).toString('hex');

  for (let i = 0; i < argRepeat; i++) {
    console.log("Minting drc-20 token...", i + 1, "of", argRepeat, "times");
    await mint(argAddress, "text/plain;charset=utf-8", encodedDoge20Tx);
  }
}

async function wallet() {
    let subcmd = process.argv[3]

    if (subcmd == 'new') {
        walletNew()
    } else if (subcmd == 'sync') {
        await walletSync()
    } else if (subcmd == 'balance') {
        walletBalance()
    } else if (subcmd == 'count') {
        walletCount()
    } else if (subcmd == 'send') {
        await walletSend()
    } else if (subcmd == 'split') {
        await walletSplit()
    } else {
        throw new Error(`unknown subcommand: ${subcmd}`)
    }
}


async function walletNew() {

    if (!fs.existsSync(WALLET_PATH)) {
        const hdPrivKey = new HDPrivateKey();
        const hotWallet = hdPrivKey.deriveChild("m/44'/236'/0'/0/0");
        const sendWallet = hdPrivKey.deriveChild("m/44'/236'/0'/1/0");
        const xprivkey = hdPrivKey.xprivkey;

        const privkey = hotWallet.privateKey.toWIF();
        const address = hotWallet.privateKey.toAddress().toString();
        const sendKey = sendWallet.privateKey.toWIF();
        const sendAddress = sendWallet.privateKey.toAddress().toString();

        const json = {
            xprivkey,
            privkey,
            address,
            sendKey,
            sendAddress,
            utxos: []
        }
        fs.writeFileSync(WALLET_PATH, JSON.stringify(json, 0, 2))
        console.log('address', address)
    } else {
        throw new Error('wallet already exists')
    }
}

async function walletSync(out = true) {
    if (process.env.TESTNET == 'true') throw new Error('no testnet api')

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    console.log('syncing utxos with dogechain.info api')

    let response = await axios.get(`https://dogechain.info/api/v1/address/unspent/${wallet.address}`)
    wallet.utxos = response.data.unspent_outputs.map(output => {
        return {
            txid: output.tx_hash,
            vout: output.tx_output_n,
            script: output.script,
            satoshis: output.value
        }
    })

    fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2))
    if (out) {
        let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
        console.log(JSON.stringify({
            balance
        }));
    }
}

async function walletSync2(out = true) {
    if (process.env.TESTNET == 'true') throw new Error('no testnet api')

    let wallet = JSON.parse(fs.readFileSync('.wallet.json'))

    let response = await axios.get(`${process.env.NODE_API_URL}/address/${wallet.address}/unspent`)
    const script = dogecore.Script.fromAddress(wallet.address).toHex();
    const unspent = (response.data.data || []).filter(node => {
        return node.height > 0;
    });
    const utxos = unspent.map(output => {
        return {
            txid: output.tx_hash,
            vout: output.tx_pos,
            script,
            satoshis: output.value
        }
    })
    utxos.sort((a, b) => {
        return b.satoshis - a.satoshis;
    })
    wallet.utxos = utxos || [];

    fs.writeFileSync('.wallet.json', JSON.stringify(wallet, 0, 2))
    if (out) {
        let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
        console.log(JSON.stringify({
            balance
        }));
    }
}


function walletBalance() {
    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)

    console.log(wallet.address, balance)
}

function walletCount() {
    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))
    console.log(wallet.address, wallet.utxos.length)
}


async function walletSend() {
    const argAddress = process.argv[4]
    const argAmount = process.argv[5]

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
    if (balance == 0) throw new Error('no funds to send')

    let receiver = new Address(argAddress)
    let amount = parseInt(argAmount)

    let tx = new Transaction()
    if (amount) {
        tx.to(receiver, amount)
        fund(wallet, tx)
    } else {
        tx.from(wallet.utxos)
        tx.change(receiver)
        tx.sign(wallet.privkey)
    }

    await broadcast(tx)

    console.log(tx.hash)
}


async function walletSplit() {
    let splits = parseInt(process.argv[4] || 100);

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH));
    const unit = parseInt(process.argv[5] || 100000000);
    const utxos = (wallet.utxos || []).filter(node => {
        return node.satoshis >= (unit * 2);
    });

    let balance = utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
    if (balance == 0) throw new Error('no funds to split')

    let tx = new Transaction()
    tx.from(utxos)
    for (let i = 0; i < splits - 1; i++) {
        tx.to(wallet.address, unit);
    }
    tx.change(wallet.address)
    tx.sign(wallet.privkey)

    await broadcast(tx)

    console.log(tx.hash)
}


const MAX_SCRIPT_ELEMENT_SIZE = 520

async function mint() {
    await walletSync(false);
    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))
    if (!wallet.sendAddress) {
        throw new Error('Missing send address');
    }
    const filepath = process.argv[3]
    const customAddress = process.argv[4]
    const sendAddress = customAddress || wallet.sendAddress;

    let address = new Address(sendAddress)
    let contentType
    let data

    if (fs.existsSync(filepath)) {
        contentType = mime.contentType(mime.lookup(filepath))
        data = fs.readFileSync(filepath)
    }

    if (data.length == 0) {
        throw new Error('no data to mint')
    }

    if (contentType.length > MAX_SCRIPT_ELEMENT_SIZE) {
        throw new Error('content type too long')
    }

    let txs = inscribe(wallet, address, contentType, data)
    // console.log(txs);
    // console.log(txs[0].outputs);
    // console.log(txs[0].getFee(), txs[0]._estimateFee());
    // console.log(txs[1].getFee(), txs[1]._estimateFee());
    // return false;

    for (let i = 0; i < txs.length; i++) {
        await broadcast(txs[i])
    }
    const result = {
        commit: txs[0].hash,
        inscription: `${txs[1].hash}i0`,
        reveal: txs[1].hash,
        sendAddress,
        sendHash: txs[txs.length - 1].hash
    }
    console.log(JSON.stringify(result));
    try {
        await new Promise(resolve => {
            setTimeout(() => {
                resolve(true)
            }, 3000);
        });
        await walletSync(false);
    } catch (e) {
    }
}


function bufferToChunk(b, type) {
    b = Buffer.from(b, type)
    return {
        buf: b.length ? b : undefined,
        len: b.length,
        opcodenum: b.length <= 75 ? b.length : b.length <= 255 ? 76 : 77
    }
}

function numberToChunk(n) {
    return {
        buf: n <= 16 ? undefined : n < 128 ? Buffer.from([n]) : Buffer.from([n % 256, n / 256]),
        len: n <= 16 ? 0 : n < 128 ? 1 : 2,
        opcodenum: n == 0 ? 0 : n <= 16 ? 80 + n : n < 128 ? 1 : 2
    }
}

function opcodeToChunk(op) {
    return { opcodenum: op }
}


const MAX_CHUNK_LEN = 240
const MAX_PAYLOAD_LEN = 1500


function inscribe(wallet, address, contentType, data) {
    let txs = []


    let privateKey = new PrivateKey(wallet.privkey)
    let publicKey = privateKey.toPublicKey()


    let parts = []
    while (data.length) {
        let part = data.slice(0, Math.min(MAX_CHUNK_LEN, data.length))
        data = data.slice(part.length)
        parts.push(part)
    }


    let inscription = new Script()
    inscription.chunks.push(bufferToChunk('ord'))
    inscription.chunks.push(numberToChunk(parts.length))
    inscription.chunks.push(bufferToChunk(contentType))
    parts.forEach((part, n) => {
        inscription.chunks.push(numberToChunk(parts.length - n - 1))
        inscription.chunks.push(bufferToChunk(part))
    })



    let p2shInput
    let lastLock
    let lastPartial

    while (inscription.chunks.length) {
        let partial = new Script()

        if (txs.length == 0) {
            partial.chunks.push(inscription.chunks.shift())
        }

        while (partial.toBuffer().length <= MAX_PAYLOAD_LEN && inscription.chunks.length) {
            partial.chunks.push(inscription.chunks.shift())
            partial.chunks.push(inscription.chunks.shift())
        }

        if (partial.toBuffer().length > MAX_PAYLOAD_LEN) {
            inscription.chunks.unshift(partial.chunks.pop())
            inscription.chunks.unshift(partial.chunks.pop())
        }


        let lock = new Script()
        lock.chunks.push(bufferToChunk(publicKey.toBuffer()))
        lock.chunks.push(opcodeToChunk(Opcode.OP_CHECKSIGVERIFY))
        partial.chunks.forEach(() => {
            lock.chunks.push(opcodeToChunk(Opcode.OP_DROP))
        })
        lock.chunks.push(opcodeToChunk(Opcode.OP_TRUE))



        let lockhash = Hash.ripemd160(Hash.sha256(lock.toBuffer()))


        let p2sh = new Script()
        p2sh.chunks.push(opcodeToChunk(Opcode.OP_HASH160))
        p2sh.chunks.push(bufferToChunk(lockhash))
        p2sh.chunks.push(opcodeToChunk(Opcode.OP_EQUAL))


        let p2shOutput = new Transaction.Output({
            script: p2sh,
            satoshis: 100000
        })


        let tx = new Transaction()
        if (p2shInput) tx.addInput(p2shInput)
        tx.addOutput(p2shOutput)
        fund(wallet, tx)

        if (p2shInput) {
            let signature = Transaction.sighash.sign(tx, privateKey, Signature.SIGHASH_ALL, 0, lastLock)
            let txsignature = Buffer.concat([signature.toBuffer(), Buffer.from([Signature.SIGHASH_ALL])])

            let unlock = new Script()
            unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
            unlock.chunks.push(bufferToChunk(txsignature))
            unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
            tx.inputs[0].setScript(unlock)
        }


        updateWallet(wallet, tx)
        txs.push(tx)

        p2shInput = new Transaction.Input({
            prevTxId: tx.hash,
            outputIndex: 0,
            output: tx.outputs[0],
            script: ''
        })

        p2shInput.clearSignatures = () => {}
        p2shInput.getSignatures = () => {}


        lastLock = lock
        lastPartial = partial

    }


    let tx = new Transaction()
    tx.addInput(p2shInput)
    tx.to(address, NFT_DUST_AMOUNT)
    fund(wallet, tx)

    let signature = Transaction.sighash.sign(tx, privateKey, Signature.SIGHASH_ALL, 0, lastLock)
    let txsignature = Buffer.concat([signature.toBuffer(), Buffer.from([Signature.SIGHASH_ALL])])

    let unlock = new Script()
    unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
    unlock.chunks.push(bufferToChunk(txsignature))
    unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
    tx.inputs[0].setScript(unlock)

    updateWallet(wallet, tx)
    txs.push(tx)


    return txs
}


function fund(wallet, tx) {
    tx.change(wallet.address)
    delete tx._fee

    for (const utxo of wallet.utxos) {
        if (tx.inputs.length && tx.outputs.length && tx.inputAmount >= tx.outputAmount + tx.getFee()) {
            break
        }

        delete tx._fee
        tx.from(utxo)
        tx.change(wallet.address)
        tx.sign(wallet.privkey)
    }

    if (tx.inputAmount < tx.outputAmount + tx.getFee()) {
        throw new Error('not enough funds')
    }
}


function updateWallet(wallet, tx) {
    wallet.utxos = wallet.utxos.filter(utxo => {
        for (const input of tx.inputs) {
            if (input.prevTxId.toString('hex') == utxo.txid && input.outputIndex == utxo.vout) {
                return false
            }
        }
        return true
    })

    tx.outputs
        .forEach((output, vout) => {
            if (output.script.toAddress().toString() == wallet.address) {
                wallet.utxos.push({
                    txid: tx.hash,
                    vout,
                    script: output.script.toHex(),
                    satoshis: output.satoshis
                })
            }
        })
}


async function broadcast(tx) {
    const body = {
        jsonrpc: "1.0",
        id: 0,
        method: "sendrawtransaction",
        params: [tx.toString()]
    }

    const options = {
        auth: {
            username: process.env.NODE_RPC_USER,
            password: process.env.NODE_RPC_PASS
        }
    }

    while (true) {
        try {
            await axios.post(process.env.NODE_RPC_URL, body, options)
            break
        } catch (e) {
            let msg = e.response && e.response.data && e.response.data.error && e.response.data.error.message
            if (msg && msg.includes('too-long-mempool-chain')) {
                console.warn('retrying, too-long-mempool-chain')
                await new Promise(resolve => setTimeout(resolve, 1000));
            } else {
                throw e
            }
        }
    }

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    updateWallet(wallet, tx)

    fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2))
}


function chunkToNumber(chunk) {
    if (chunk.opcodenum == 0) return 0
    if (chunk.opcodenum == 1) return chunk.buf[0]
    if (chunk.opcodenum == 2) return chunk.buf[1] * 255 + chunk.buf[0]
    if (chunk.opcodenum > 80 && chunk.opcodenum <= 96) return chunk.opcodenum - 80
    return undefined
}


async function extract(txid) {
    let resp = await axios.get(`https://dogechain.info/api/v1/transaction/${txid}`)
    let transaction = resp.data.transaction
    let script = Script.fromHex(transaction.inputs[0].scriptSig.hex)
    let chunks = script.chunks


    let prefix = chunks.shift().buf.toString('utf8')
    if (prefix != 'ord') {
        throw new Error('not a doginal')
    }

    let pieces = chunkToNumber(chunks.shift())

    let contentType = chunks.shift().buf.toString('utf8')


    let data = Buffer.alloc(0)
    let remaining = pieces

    while (remaining && chunks.length) {
        let n = chunkToNumber(chunks.shift())

        if (n !== remaining - 1) {
            txid = transaction.outputs[0].spent.hash
            resp = await axios.get(`https://dogechain.info/api/v1/transaction/${txid}`)
            transaction = resp.data.transaction
            script = Script.fromHex(transaction.inputs[0].scriptSig.hex)
            chunks = script.chunks
            continue
        }

        data = Buffer.concat([data, chunks.shift().buf])
        remaining -= 1
    }

    return {
        contentType,
        data
    }
}


function server() {
    const app = express()
    const port = process.env.SERVER_PORT ? parseInt(process.env.SERVER_PORT) : 3000

    app.get('/tx/:txid', (req, res) => {
        extract(req.params.txid).then(result => {
            res.setHeader('content-type', result.contentType)
            res.send(result.data)
        }).catch(e => res.send(e.message))
    })

    app.listen(port, () => {
        console.log(`Listening on port ${port}`)
        console.log()
        console.log(`Example:`)
        console.log(`http://localhost:${port}/tx/15f3b73df7e5c072becb1d84191843ba080734805addfccb650929719080f62e`)
    })
}


main().catch(e => {
    shutdown();
    let reason = e.response && e.response.data && e.response.data.error && e.response.data.error.message
    throw reason;
}).finally(() => {
    shutdown();
})
