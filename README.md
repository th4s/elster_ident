# ElsterIdent

## Experimental repository
**Do not use in production!!! This is only a proof of concept!!!**

## Description
A little toy crate to check possibilities of using TLSNotary to verify ones identity
based on Elster Portal.

## Usage
1. Log in to <https://www.elster.de/eportal/meinestammdaten>
2. Go to the network tab of your browser and copy the value of the request
   header `Cookie`. This will look like `JSESSIONID=...; LANGUAGE=...`.
3. In a terminal start the notary server:
```bash
cargo run --bin notary --release -- --config-file notary-config.yaml
```
4. In another terminal start the prover:
```bash
COOKIE='<COOKIE-VALUE>' cargo run --bin prover --release
```
5. Wait until the notarization is finished, should be 1-2 minutes.
6. Go to <https://tlsnotary.github.io/proof_viz/> and drop your
   `elster_proof.json` there, which was generated during the notarization.
   Search for your name or birthday.
7. Congrats you just proved your identity using TLSNotary and Elster.
