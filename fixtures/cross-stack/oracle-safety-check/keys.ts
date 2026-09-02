// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic key derivation for the insight.oracle-safety-check:v2
// cross-stack vectors. Self-contained copy of the derivation rules from the
// upstream generator (agent-passport-system fixtures/oracle-safety-check/
// generate-fixtures.ts) so this runner depends on nothing from the generator.
//
//   seed      = SHA-256(utf8(SEED_INPUT))
//   role_seed = SHA-256(utf8(SEED_INPUT) || 0x00 || utf8(role))
//   Ed25519   : private key = role_seed (RFC 8032), public key = derivation
//   secp256k1 : private key = role_seed, address = keccak256(pubkey)[-20:]

import crypto from 'node:crypto'
import { privateKeyToAccount } from 'viem/accounts'

export const SEED_INPUT = 'aps-oracle-safety-check-fixture-v1'
export const BASELINE_MS = Date.UTC(2026, 7, 25, 0, 0, 0) // 2026-08-25T00:00:00.000Z

export const PRINCIPAL_DID = 'did:aps:insight-principal-001'
export const AGENT_DID = 'did:aps:insight-agent-001'
export const GATEWAY_DID = 'did:aps:insight-gateway-001'

export type KeyRole = 'principal' | 'agent' | 'gateway' | 'evm-attester'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function roleSeedBytes(role: KeyRole): Buffer {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from(SEED_INPUT, 'utf8'), Buffer.from([0x00]), Buffer.from(role, 'utf8')]))
    .digest()
}

export interface Ed25519Keypair {
  privateKeyHex: string
  publicKeyHex: string
}

function ed25519FromSeed(seed: Buffer): Ed25519Keypair {
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubDer = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' })
  return {
    privateKeyHex: seed.toString('hex'),
    publicKeyHex: Buffer.from(pubDer.slice(-32)).toString('hex'),
  }
}

const keyCache = new Map<KeyRole, Ed25519Keypair>()

export function deriveEd25519(role: Exclude<KeyRole, 'evm-attester'>): Ed25519Keypair {
  const cached = keyCache.get(role)
  if (cached) return cached
  const kp = ed25519FromSeed(roleSeedBytes(role))
  keyCache.set(role, kp)
  return kp
}

export function evmAttesterAddress(): `0x${string}` {
  const seed = roleSeedBytes('evm-attester')
  const account = privateKeyToAccount(`0x${seed.toString('hex')}` as `0x${string}`)
  return account.address
}
