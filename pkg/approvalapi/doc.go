// Package approvalapi is the public contract for Gatecrasher's approval API, version 1:
// the request and response types, the request digest, and verification of signed
// decisions. Producers such as Warden import it; the server implements it.
//
// The OpenAPI description is api/openapi/gate-v1.yaml in this repository. The two must
// agree; a change to either is a change to the contract.
package approvalapi
