// Prints a JSON array: canonicalize(policy_input) for each vector, in file order.
import { readFileSync } from 'node:fs'
import canonicalize from 'canonicalize'

const doc = JSON.parse(readFileSync(process.argv[2], 'utf8'))
process.stdout.write(JSON.stringify(doc.vectors.map((v) => canonicalize(v.policy_input))))
