# FROST KeyGen Parameter Explanation

## Overview
FROST is a threshold signature protocol based on Schnorr signatures. In the KeyGen phase, \(n\) participants jointly generate a single public/private key pair under a threshold \(t\) (meaning at least \(t\) participants need to cooperate to sign). Each participant ends up with their own long-lived private signing share. Below is an explanation of each parameter in sequence.

---

## Round 1

### 1. Polynomial Coefficients and Polynomials
- **\(a_{i0}, \dots, a_{i(t-1)} \in \mathbb{Z}_q\)**
  - Participant \(P_i\) (the \(i\)-th participant) independently samples \(t\) coefficients from the finite field \(\mathbb{Z}_q\).
  - Among these, \(a_{i0}\) is the constant term of the polynomial, used later in the Schnorr-style proof.
- **\(f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^j\)**
  - Each participant \(P_i\) constructs a polynomial of degree \(t-1\) from these coefficients.
  - The polynomial will be evaluated at specific indices (the other participants), achieving secret sharing.

### 2. Schnorr Proof Parameters
- **\(\sigma_i = (R_i, \mu_i)\)**
  - Schnorr-style zero-knowledge proof of \(a_{i0}\) by \(P_i\).
  - Steps:
    1. Sample \(k\) from \(\mathbb{Z}_q\), compute \(R_i = g^k\).
    2. Compute challenge \(c_i = H(i, \Phi, g^{a_{i0}}, R_i)\).
    3. Compute response \(\mu_i = k + a_{i0} \cdot c_i\).
  - Where:
    - \(k\) is private nonce
    - \(a_{i0}\)is private key (local)
    - \(R_i\) is public nonce
- **\(R_i\)**
  - The temporary commitment in the Schnorr proof.
- **\(c_i\)**
  - The challenge linking \(R_i\) and \(a_{i0}\).
- **\(\mu_i\)**
  - The Schnorr response containing the participant’s secret contribution.

### 3. Public Commitment \(\widetilde{C}_i\)
- **\(\widetilde{C}_i = \langle \phi_{i0}, \dots, \phi_{i(t-1)} \rangle\)**
  - A vector of commitments to the polynomial coefficients \(\phi_{ij} = g^{a_{ij}}\).
  - Used later for share verification.

### 4. Broadcast
- \(P_i\) broadcasts \(\widetilde{C}_i\) and \(\sigma_i\) to prove possession of \(a_{i0}\).

### 5. Verifying Other Participants’ Schnorr Proofs
- Upon receiving \(\widetilde{C}_\ell\) and \(\sigma_\ell = (R_\ell, \mu_\ell)\) from \(P_\ell\), \(P_i\) checks:
  \[
  R_\ell \stackrel{?}{=} g^{\mu_\ell} \cdot \phi_{\ell0}^{-c_\ell},
  \]
  where
  \[  c_\ell = H(\ell, \Phi, \phi_{\ell0}, R_\ell).  \]
- If verification fails, abort.

---

## Round 2

### 1. Distributing Secret Shares
- Each \(P_i\) securely sends \((\ell, f_i(\ell))\) to each other \(P_\ell\).

### 2. Verifying Received Shares
- For each share \(f_e(i)\) from \(P_e\), check:
  \[
  g^{f_e(i)} \stackrel{?}{=} \prod_{k=0}^{t-1} \phi_{ek}^{i^k}.
  \]
- Abort if the check fails.

### 3. Computing Long-Lived Private Signing Share
- **\(s_i = \sum_{\ell=1}^{n} f_\ell(i)\)**
  - \(P_i\) sums up all shares received to get its private signing share \(s_i\).

### 4. Computing Public Verification Value
- **\(Y_i = g^{s_i}\)**
  - The public verification share of \(P_i\).
- **\(Y = \prod_{j=1}^n \phi_{j0}\)**
  - The group public key, i.e., \(g^{\sum_j a_{j0}}\).
- Alternatively,
  \[  Y_i = \prod_{j=1}^{n} \prod_{k=0}^{t-1} \phi_{jk}^{i^k}.  \]

---

## Summary
- **\(a_{ij}\)**: The polynomial coefficients of participant \(P_i\).
- **\(f_i(x)\)**: The polynomial of participant \(P_i\).
- **\(\phi_{ij} = g^{a_{ij}}\)**: Commitments to the coefficients.
- **\(\widetilde{C}_i = \langle \phi_{i0}, \ldots, \phi_{i(t-1)} \rangle\)**: Public commitment vector for \(P_i\).
- **\((R_i, \mu_i)\)**: Schnorr proof for \(a_{i0}\).
- **\(k, R_i = g^k, c_i, \mu_i = k + a_{i0} \cdot c_i\)**: Randomness, commitment, challenge, and response in the Schnorr proof.
- **\(f_i(\ell)\)**: The secret share from \(P_i\) to \(P_\ell\).
- **\(s_i = \sum_{\ell=1}^n f_\ell(i)\)**: Long-lived private signing share of \(P_i\).
- **\(Y_i = g^{s_i}\)**: Public verification share of \(P_i\).
- **\(Y = \prod_{j=1}^n \phi_{j0}\)**: The group public key.

FROST thus securely generates a distributed threshold-based Schnorr key pair, with each participant holding only their respective share.


## TODO
1. confidential channel for round2
2. BTC is not suitable