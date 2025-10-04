;; NanoAcademic - Zero-Knowledge Identity Verification System
;; A privacy-preserving academic credentials platform

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-credential (err u104))
(define-constant err-not-matured (err u105))
(define-constant err-invalid-attestation (err u106))

;; Maturation periods (in blocks)
(define-constant basic-maturation u144) ;; ~1 day
(define-constant full-maturation u1008) ;; ~1 week

;; Data Variables
(define-data-var credential-nonce uint u0)
(define-data-var attestation-nonce uint u0)

;; Data Maps

;; Institutions registry
(define-map institutions
    principal
    {
        name: (string-ascii 100),
        verified: bool,
        registration-height: uint,
        total-credentials-issued: uint
    }
)

;; Nano-credentials storage (Merkle root commitment)
(define-map nano-credentials
    uint ;; credential-id
    {
        institution: principal,
        merkle-root: (buff 32),
        credential-type: (string-ascii 50),
        issue-height: uint,
        maturation-level: uint,
        attestation-count: uint,
        revoked: bool
    }
)

;; Student credentials mapping (privacy-preserving)
(define-map student-credentials
    principal ;; student address
    (list 50 uint) ;; credential-ids
)

;; Cryptographic attestations from peers
(define-map attestations
    uint ;; attestation-id
    {
        credential-id: uint,
        attestor: principal,
        attestation-hash: (buff 32),
        timestamp: uint,
        weight: uint
    }
)

;; Verification proofs (zero-knowledge proof references)
(define-map verification-proofs
    {credential-id: uint, verifier: principal}
    {
        proof-hash: (buff 32),
        verified-at: uint,
        disclosure-level: uint
    }
)

;; Credential type templates
(define-map credential-templates
    (string-ascii 50) ;; credential-type
    {
        min-attestations: uint,
        maturation-blocks: uint,
        disclosure-rings: (list 10 uint)
    }
)

;; Read-only functions

;; Get institution details
(define-read-only (get-institution (institution principal))
    (map-get? institutions institution)
)

;; Get nano-credential details
(define-read-only (get-credential (credential-id uint))
    (map-get? nano-credentials credential-id)
)

;; Get student's credentials
(define-read-only (get-student-credentials (student principal))
    (default-to (list) (map-get? student-credentials student))
)

;; Calculate maturation level based on time and attestations
(define-read-only (calculate-maturation-level (credential-id uint))
    (match (map-get? nano-credentials credential-id)
        credential
        (let
            (
                (blocks-passed (- block-height (get issue-height credential)))
                (attestation-count (get attestation-count credential))
                (base-level (if (>= blocks-passed full-maturation) u100
                               (if (>= blocks-passed basic-maturation) u50 u0)))
                (attestation-bonus (/ (* attestation-count u10) u1))
            )
            (ok (+ base-level (if (<= attestation-bonus u50) attestation-bonus u50)))
        )
        (err err-not-found)
    )
)

;; Check if credential is fully matured
(define-read-only (is-credential-matured (credential-id uint))
    (match (map-get? nano-credentials credential-id)
        credential
        (let
            (
                (blocks-passed (- block-height (get issue-height credential)))
            )
            (ok (>= blocks-passed full-maturation))
        )
        (err err-not-found)
    )
)

;; Get attestation details
(define-read-only (get-attestation (attestation-id uint))
    (map-get? attestations attestation-id)
)

;; Get verification proof
(define-read-only (get-verification-proof (credential-id uint) (verifier principal))
    (map-get? verification-proofs {credential-id: credential-id, verifier: verifier})
)

;; Get credential template
(define-read-only (get-credential-template (cred-type (string-ascii 50)))
    (map-get? credential-templates cred-type)
)

;; Public functions

;; Register institution (owner only)
(define-public (register-institution (institution principal) (name (string-ascii 100)))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (is-none (map-get? institutions institution)) err-already-exists)
        (ok (map-set institutions institution
            {
                name: name,
                verified: true,
                registration-height: block-height,
                total-credentials-issued: u0
            }
        ))
    )
)

;; Create credential template (owner only)
(define-public (create-credential-template 
    (cred-type (string-ascii 50))
    (min-attestations uint)
    (maturation-blocks uint)
    (disclosure-rings (list 10 uint)))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set credential-templates cred-type
            {
                min-attestations: min-attestations,
                maturation-blocks: maturation-blocks,
                disclosure-rings: disclosure-rings
            }
        ))
    )
)

;; Mint nano-credential (institution only)
(define-public (mint-nano-credential 
    (student principal)
    (merkle-root (buff 32))
    (credential-type (string-ascii 50)))
    (let
        (
            (credential-id (var-get credential-nonce))
            (institution-data (unwrap! (map-get? institutions tx-sender) err-unauthorized))
        )
        (asserts! (get verified institution-data) err-unauthorized)
        
        ;; Create nano-credential
        (map-set nano-credentials credential-id
            {
                institution: tx-sender,
                merkle-root: merkle-root,
                credential-type: credential-type,
                issue-height: block-height,
                maturation-level: u0,
                attestation-count: u0,
                revoked: false
            }
        )
        
        ;; Update student's credential list
        (let
            (
                (current-creds (default-to (list) (map-get? student-credentials student)))
            )
            (map-set student-credentials student
                (unwrap! (as-max-len? (append current-creds credential-id) u50) err-invalid-credential))
        )
        
        ;; Update institution stats
        (map-set institutions tx-sender
            (merge institution-data {total-credentials-issued: (+ (get total-credentials-issued institution-data) u1)})
        )
        
        ;; Increment nonce
        (var-set credential-nonce (+ credential-id u1))
        (ok credential-id)
    )
)

;; Add cryptographic attestation
(define-public (add-attestation 
    (credential-id uint)
    (attestation-hash (buff 32))
    (weight uint))
    (let
        (
            (attestation-id (var-get attestation-nonce))
            (credential (unwrap! (map-get? nano-credentials credential-id) err-not-found))
        )
        (asserts! (not (get revoked credential)) err-invalid-credential)
        
        ;; Create attestation
        (map-set attestations attestation-id
            {
                credential-id: credential-id,
                attestor: tx-sender,
                attestation-hash: attestation-hash,
                timestamp: block-height,
                weight: weight
            }
        )
        
        ;; Update credential attestation count
        (map-set nano-credentials credential-id
            (merge credential {attestation-count: (+ (get attestation-count credential) u1)})
        )
        
        ;; Increment attestation nonce
        (var-set attestation-nonce (+ attestation-id u1))
        (ok attestation-id)
    )
)

;; Submit verification proof (zero-knowledge)
(define-public (submit-verification-proof
    (credential-id uint)
    (proof-hash (buff 32))
    (disclosure-level uint))
    (let
        (
            (credential (unwrap! (map-get? nano-credentials credential-id) err-not-found))
        )
        (asserts! (not (get revoked credential)) err-invalid-credential)
        
        ;; Store verification proof
        (ok (map-set verification-proofs 
            {credential-id: credential-id, verifier: tx-sender}
            {
                proof-hash: proof-hash,
                verified-at: block-height,
                disclosure-level: disclosure-level
            }
        ))
    )
)

;; Revoke credential (institution only)
(define-public (revoke-credential (credential-id uint))
    (let
        (
            (credential (unwrap! (map-get? nano-credentials credential-id) err-not-found))
        )
        (asserts! (is-eq tx-sender (get institution credential)) err-unauthorized)
        (ok (map-set nano-credentials credential-id
            (merge credential {revoked: true})
        ))
    )
)

;; Update maturation level (called periodically or by attestations)
(define-public (update-maturation (credential-id uint))
    (let
        (
            (credential (unwrap! (map-get? nano-credentials credential-id) err-not-found))
            (new-level (unwrap! (calculate-maturation-level credential-id) err-not-found))
        )
        (ok (map-set nano-credentials credential-id
            (merge credential {maturation-level: new-level})
        ))
    )
)

;; Batch mint credentials (gas efficient)
(define-public (batch-mint-credentials
    (students (list 10 principal))
    (merkle-roots (list 10 (buff 32)))
    (credential-type (string-ascii 50)))
    (let
        (
            (institution-data (unwrap! (map-get? institutions tx-sender) err-unauthorized))
        )
        (asserts! (get verified institution-data) err-unauthorized)
        (ok (map batch-mint-helper 
            students 
            merkle-roots))
    )
)

;; Helper function for batch minting
(define-private (batch-mint-helper (student principal) (merkle-root (buff 32)))
    (let
        (
            (credential-id (var-get credential-nonce))
        )
        (map-set nano-credentials credential-id
            {
                institution: tx-sender,
                merkle-root: merkle-root,
                credential-type: "batch-credential",
                issue-height: block-height,
                maturation-level: u0,
                attestation-count: u0,
                revoked: false
            }
        )
        (var-set credential-nonce (+ credential-id u1))
        credential-id
    )
)

;; Initialize contract with default templates
(map-set credential-templates "undergraduate-degree"
    {
        min-attestations: u3,
        maturation-blocks: full-maturation,
        disclosure-rings: (list u1 u2 u3 u4 u5)
    }
)

(map-set credential-templates "graduate-degree"
    {
        min-attestations: u5,
        maturation-blocks: full-maturation,
        disclosure-rings: (list u1 u2 u3 u4 u5 u6 u7)
    }
)

(map-set credential-templates "certificate"
    {
        min-attestations: u2,
        maturation-blocks: basic-maturation,
        disclosure-rings: (list u1 u2 u3)
    }
)
