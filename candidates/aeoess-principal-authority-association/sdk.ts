// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The SDK surface this candidate family uses, in one place.
//
// agent-passport-system 7.1.0, the version the lab pins, compiles
// issuePrincipalBindingV1 and verifyPrincipalBindingV1 into
// dist/src/v2/identity-binding/principal-binding.js but exports neither from the
// package root or from ./core. The package `exports` map blocks a subpath import,
// so this file loads the compiled module by file URL, resolved next to the
// package entry. That calls the published SDK code unchanged. It is not the
// package's public API, and the README records it as such.
//
// Everything else comes from the package root.

import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

export {
  canonicalizeJCS,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
  verify,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationBodyV1,
  type AuthorityDelegationV1,
} from 'agent-passport-system'

const ENTRY = import.meta.resolve('agent-passport-system')

export const PRINCIPAL_BINDING_MODULE = 'dist/src/v2/identity-binding/principal-binding.js'

export const SDK_VERSION = JSON.parse(
  fs.readFileSync(fileURLToPath(new URL('../../package.json', ENTRY)), 'utf8'),
).version as string

// Local copy of the shapes, because 7.1.0 does not export the PrincipalBindingV1
// type from the package root either.
export interface PrincipalBindingV1 {
  record_type: 'aps.principal-binding'
  version: '1.0'
  binding_id: string
  agent_id: string
  principal_id: string
  verification_method: string
  audiences: string[]
  authority_profiles: string[]
  status_uri: string
  issued_at: string
  expires_at: string
  nonce: string
  signature: string
}

export interface IdentityVerificationResult {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  code: string
}

type KeyResolution = { state: 'resolved' | 'not_found'; public_key_hex?: string }

interface PrincipalBindingModule {
  issuePrincipalBindingV1(input: {
    agent_id: string
    principal_id: string
    verification_method: string
    audiences: readonly string[]
    authority_profiles: readonly string[]
    status_uri: string
    issued_at: string
    expires_at: string
    nonce: string
    principal_private_key_hex: string
  }): PrincipalBindingV1
  verifyPrincipalBindingV1(
    candidate: unknown,
    options: {
      now: string
      resolve_key: (request: { controller: string; verification_method: string; at: string }) => KeyResolution
    },
  ): Promise<IdentityVerificationResult>
}

const principalBinding = (await import(
  new URL('./v2/identity-binding/principal-binding.js', ENTRY).href
)) as PrincipalBindingModule

export const issuePrincipalBindingV1 = principalBinding.issuePrincipalBindingV1
export const verifyPrincipalBindingV1 = principalBinding.verifyPrincipalBindingV1
