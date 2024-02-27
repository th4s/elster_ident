# ElsterIdent

## Experimental repository
**Do not use in production!!! This is only a proof of concept!!!**

## Description
A little toy crate to check possibilities of using TLSNotary to verify ones identity
based on Elster Portal.

## Usage
1. In a terminal start the notary server:
```bash
cargo run --bin notary --release -- --config-file notary-config.yaml
```
2. In another terminal start the prover:
```bash
cargo run --bin prover --release
```
3. Scan the QR-code with ElsterSecure App.
4. Wait until the notarization is finished, should be 1-2 minutes.
5. Go to <https://tlsnotary.github.io/proof_viz/> and drop your
   `elster_proof.json` there, which was just generated. No worries, this is only
   in the browser, no data upload.
6. Congrats you just proved your identity using Elster and TLSNotary.
