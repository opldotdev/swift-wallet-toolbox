// Vectors for Tests/ToolboxWalletTests/MessageBoxAdvertisementTests.swift.
//
// `@bsv/message-box-client` 2.7.0 `anointHost` locks the advertisement with
// `pushdrop.lock([identityKey, host], [1, 'messagebox advertisement'], '1', 'anyone', true)` and
// spends one with `pushdrop.unlock([1, 'messagebox advertisement'], '1', 'anyone', 'all', false,
// satoshis, lockingScript)`. This reproduces both with `@bsv/sdk` 4.1.0, offline.
//
//   bun add @bsv/sdk@4.1.0 && bun run messagebox-advertisement-vectors.ts
import { PrivateKey, ProtoWallet, PushDrop, Transaction, Utils, LockingScript, Spend } from '@bsv/sdk'

const root = PrivateKey.fromHex('6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede')
const wallet = new ProtoWallet(root)
const identityKey = root.toPublicKey().toString()

async function advert (host: string): Promise<LockingScript> {
  const fields = [Utils.toArray(identityKey, 'hex'), Utils.toArray(host, 'utf8')]
  return await new PushDrop(wallet).lock(fields, [1, 'messagebox advertisement'], '1', 'anyone', true)
}

const oneSat = await advert('https://messagebox.1sat.app')
const bsvb = await advert('https://messagebox.bsvblockchain.tech')
// The 1Sat advertisement's own transaction: no inputs, one 1-satoshi output.
const source = new Transaction(1, [], [{ satoshis: 1, lockingScript: oneSat }], 0)

async function unlock (outputs: Array<{ satoshis: number, lockingScript: LockingScript }>): Promise<string> {
  const tx = new Transaction(1, [{
    sourceTXID: source.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: undefined as any
  }], outputs, 0)
  const unlocking = await new PushDrop(wallet)
    .unlock([1, 'messagebox advertisement'], '1', 'anyone', 'all', false, 1, oneSat).sign(tx, 0)
  const spend = new Spend({
    sourceTXID: source.id('hex'), sourceOutputIndex: 0, sourceSatoshis: 1, lockingScript: oneSat,
    transactionVersion: 1, otherInputs: [], outputs, inputIndex: 0, unlockingScript: unlocking,
    inputSequence: 0xffffffff, lockTime: 0
  })
  if (!spend.validate()) throw new Error('unlock does not validate')
  return unlocking.toHex()
}

console.log(JSON.stringify({
  identityKey,
  oneSatLock: oneSat.toHex(),
  bsvbLock: bsvb.toHex(),
  sourceTxid: source.id('hex'),
  // An anoint that moves the host: the one output is the new advertisement.
  anointUnlocking: await unlock([{ satoshis: 1, lockingScript: bsvb }]),
  // A revoke: no outputs.
  revokeUnlocking: await unlock([])
}, null, 2))
