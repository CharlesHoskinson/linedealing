// Midnight Preview glue for the split-line committee (LOOP item 34).
//
// The committee key is a BIP340 x-only key. This script holds no signing key
// for it: the unshielded wallet is started from the committee's public key and
// every segment it must sign is sent to the Rust caller ("sign" event), which
// answers with a committee threshold signature. The SDK documents this path
// for MPC and HSM signers (SignSegment).
//
// The DUST and shielded wallets come from a test-local seed that the caller
// passes on stdin. DUST pays fees only; it holds no funds.
//
// It uses the already-installed SDK in the Moriarty sherlock-sdk (ledger 9.1.0.1
// stack: wallet-sdk 2.0.0, ledger-v9 1.0.0). It installs nothing.
//
// Commands:
//   address <vk-hex>                  -> {"address","addressHex"}
//   verify <vk-hex> <data-hex> <sig-hex> -> true | false (ledger verifySignature)
//   session                           -> JSON-lines protocol on stdin/stdout
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';

const SDK_ROOT = process.env.MIDNIGHT_SDK_ROOT
  || join(process.env.HOME, 'Projects/Moriarty/tools/sherlock-sdk');
const NETWORK_ID = 'preview';
const GENESIS = '0x3c096de209e06a1a8c52be7bda109ee8c891a42288c0a9db5495f9616dd13796';
const endpoints = {
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWs: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  rpc: 'wss://rpc.preview.midnight.network',
  rpcHttp: 'https://rpc.preview.midnight.network',
  proof: process.env.MIDNIGHT_PROOF_URL || 'http://127.0.0.1:6300',
};
const PROOF_SERVER_ACCEPTED = ['9.0.0', '9.0.1'];
const PINNED = {'@midnightntwrk/wallet-sdk': '2.0.0', '@midnightntwrk/ledger-v9': '1.0.0'};

async function imp(spec) {
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  const sub = '.' + spec.slice(name.length);
  const dir = join(SDK_ROOT, 'node_modules', name);
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json')));
  let target = pkg.exports ? pkg.exports[sub] : (sub === '.' ? pkg.main : sub);
  for (let i = 0; target && typeof target === 'object' && i < 4; i++)
    target = target.node ?? target.import ?? target.default;
  return import(pathToFileURL(join(dir, target)).href);
}
async function loadSdk() {
  for (const [name, version] of Object.entries(PINNED)) {
    const v = JSON.parse(readFileSync(join(SDK_ROOT, 'node_modules', name, 'package.json'))).version;
    if (v !== version) throw Error(`${name} is ${v}, expected ${version}`);
  }
  return {sdk: await imp('@midnightntwrk/wallet-sdk'), ledger: await imp('@midnightntwrk/wallet-sdk/ledger/v9'),
    Rx: await imp('rxjs')};
}
const emit = obj => process.stdout.write(JSON.stringify(obj, (_, v) => typeof v === 'bigint' ? v.toString() : v) + '\n');
const log = (...a) => console.error('[mn]', ...a);
// submitTransaction returns a segment identifier (66 hex). The indexer and the
// explorer key transactions by their 64-hex hash; ask the indexer for it.
async function txHash(identifier) {
  const query = `{ transactions(offset:{identifier:"${identifier}"}) { hash block { height } } }`;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(endpoints.indexer, {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({query})});
      const tx = (await r.json())?.data?.transactions?.[0];
      if (tx?.hash) return {hash: tx.hash, block: tx.block?.height};
    } catch (error) { log('indexer:', error?.message ?? error); }
    await new Promise(r => setTimeout(r, 10_000));
  }
  return {hash: null, block: null};
}

function identity({sdk, ledger}, vkHex) {
  const publicKey = {tag: 'schnorr', value: vkHex};
  const addressHex = ledger.addressFromKey(publicKey);
  const address = sdk.UnshieldedAddress.codec
    .encode(NETWORK_ID, new sdk.UnshieldedAddress(Buffer.from(addressHex, 'hex'))).asString();
  return {publicKey, addressHex, address};
}

async function checkNetwork() {
  const r = await fetch(endpoints.rpcHttp, {method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'chain_getBlockHash', params: [0]})});
  const g = (await r.json()).result;
  if (g !== GENESIS) throw Error(`Preview genesis mismatch: ${g}`);
  const version = (await (await fetch(new URL('version', endpoints.proof))).text()).trim();
  if (!PROOF_SERVER_ACCEPTED.includes(version)) throw Error(`proof server ${version} not accepted for ledger 9.1.0.1`);
  return version;
}

async function session() {
  const kit = await loadSdk();
  const {sdk, Rx} = kit;
  const {WebSocket} = await imp('ws');
  globalThis.WebSocket ??= WebSocket;
  const lines = createInterface({input: process.stdin})[Symbol.asyncIterator]();
  const next = async () => JSON.parse((await lines.next()).value);
  const init = await next();
  const id = identity(kit, init.vk);
  const proofVersion = await checkNetwork();
  emit({event: 'identity', address: id.address, proofServer: proofVersion});
  // Every segment signature comes from the committee through the caller.
  const signSegment = async data => {
    emit({event: 'sign', data: Buffer.from(data).toString('hex')});
    const reply = await next();
    const signature = {tag: 'schnorr', value: reply.sig};
    if (!kit.ledger.verifySignature(id.publicKey, data, signature)) throw Error('committee signature rejected by ledger');
    return signature;
  };
  const seeds = sdk.WalletSeeds.fromMasterSeed(Buffer.from(init.walletSeed, 'hex'));
  const configuration = {networkId: NETWORK_ID, costParameters: {feeBlocksMargin: 5},
    relayURL: new URL(endpoints.rpc), provingServerUrl: new URL(endpoints.proof),
    indexerClientConnection: {indexerHttpUrl: endpoints.indexer, indexerWsUrl: endpoints.indexerWs},
    txHistoryStorage: new sdk.NoOpTransactionHistoryStorage()};
  const wallet = await sdk.WalletFacade.init({configuration,
    shielded: cfg => sdk.ShieldedWallet(cfg).startWithSeed(seeds.shielded),
    unshielded: cfg => sdk.UnshieldedWallet(cfg).startWithPublicKey(id),
    dust: cfg => sdk.DustWallet(cfg).startWithSeed(seeds.dust)});
  await wallet.start(seeds);
  const night = sdk.Token.night;
  // Ledger well-formedness check (balance, signatures, limits) of the proven
  // transaction before broadcast: a proof server or ledger mismatch stops here.
  // The SDK checks against LedgerState.blank, which holds no DUST generation
  // record for our NIGHT UTXO. A registration pays its fee from that UTXO's
  // registration allowance, so in a blank state it always reads "0 available".
  // The registration is therefore checked without balancing; the node checks
  // its balance against the real state on submit.
  const validate = async (tx, enforceBalancing = true) => {
    await wallet.validateTransaction(tx, {flags: {enforceBalancing, verifySignatures: true, enforceLimits: true}});
    emit({event: 'validated', enforceBalancing});
  };
  const timeoutMs = Number(init.waitSecs ?? 3600) * 1000;
  const state = (pred, what) => Rx.firstValueFrom(wallet.state().pipe(
    Rx.filter(s => s.isSynced && pred(s)), Rx.timeout({first: timeoutMs, with: () => Rx.throwError(() => Error(`timeout: ${what}`))})));
  try {
    let s = await state(() => true, 'sync');
    const nightCoins = st => st.unshielded.availableCoins.filter(c => c.utxo.type === night);
    emit({event: 'synced', night: s.unshielded.balances[night] ?? 0n, utxos: nightCoins(s).length,
      dust: s.dust.balance(new Date())});
    if (nightCoins(s).length === 0) {
      // Ask again every minute, so a funding script that appears later is used.
      const until = Date.now() + timeoutMs;
      for (;;) {
        emit({event: 'need-funds', address: id.address});
        try {
          s = await Rx.firstValueFrom(wallet.state().pipe(
            Rx.filter(st => st.isSynced && nightCoins(st).length > 0), Rx.timeout({first: 60_000})));
          break;
        } catch (error) {
          if (Date.now() > until) throw Error('timeout: NIGHT funds');
        }
      }
    }
    const unregistered = nightCoins(s).filter(c => !c.meta.registeredForDustGeneration);
    if (unregistered.length > 0) {
      const {fee, dustGenerationEstimations} = await wallet.estimateRegistration(unregistered);
      emit({event: 'registration-estimate', fee, generation: dustGenerationEstimations});
      await wallet.waitForGeneratedDust(unregistered, fee, {timeoutMs});
      const recipe = await wallet.registerNightUtxosForDustGeneration(unregistered, id.publicKey, signSegment);
      const tx = await wallet.finalizeRecipe(recipe);
      await validate(tx, false);
      const txId = String(await wallet.submitTransaction(tx));
      emit({event: 'submitted', kind: 'dust-registration', txId, ...await txHash(txId)});
      s = await state(st => nightCoins(st).length > 0 && nightCoins(st).every(c => c.meta.registeredForDustGeneration),
        'registration in a block');
    }
    // Spend all NIGHT back to the funding wallet; DUST pays the fee.
    const amount = s.unshielded.balances[night];
    const receiverAddress = sdk.MidnightBech32m.parse(init.returnAddress).decode(sdk.UnshieldedAddress, NETWORK_ID);
    const ttl = () => new Date(Date.now() + 30 * 60 * 1000);
    let recipe;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        recipe = await wallet.transferTransaction(
          [{type: 'unshielded', outputs: [{amount, receiverAddress, type: night}]}], {ttl: ttl()});
        break;
      } catch (error) {
        if (Date.now() > deadline) throw error;
        log('transfer not yet payable, waiting for DUST:', error?.message ?? error);
        await new Promise(r => setTimeout(r, 60_000));
      }
    }
    const signed = await wallet.signRecipe(recipe, signSegment);
    const tx = await wallet.finalizeRecipe(signed);
    await validate(tx);
    const txId = String(await wallet.submitTransaction(tx));
    emit({event: 'submitted', kind: 'transfer', txId, amount, ...await txHash(txId)});
    await state(st => (st.unshielded.balances[night] ?? 0n) === 0n
      && (st.unshielded.pendingCoins ?? []).length === 0, 'transfer in a block');
    emit({event: 'done', txId});
  } finally {
    await wallet.stop();
  }
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'address') {
  const kit = await loadSdk();
  const id = identity(kit, args[0]);
  emit({address: id.address, addressHex: id.addressHex});
} else if (cmd === 'verify') {
  const {ledger} = await loadSdk();
  console.log(ledger.verifySignature({tag: 'schnorr', value: args[0]}, Buffer.from(args[1], 'hex'),
    {tag: 'schnorr', value: args[2]}));
} else if (cmd === 'session') {
  await session();
  process.exit(0);
} else {
  console.error('usage: mn.mjs address <vk> | verify <vk> <data> <sig> | session');
  process.exit(2);
}
