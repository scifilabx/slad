# SLAD

Tools for signing **your own** software releases with an Ed25519 key.

No server, no account, no middleman. Users verify the signature locally —
they do not have to trust the author, GitHub, or anyone else.

**This is not a token and not a cryptocurrency.**

## Quick start

```bash
pip install requests pynacl cryptography
ipfs init && ipfs daemon          # IPFS node (separate terminal)

python3 tools/slad_protokolu.py nowy-portfel
```

**Write the seed down on paper** — without it the key is lost forever.
The wallet is created in *your* home directory (`~/.slad/`).

## Sign your release

```bash
cd <your-repo>
SLAD_HASLO='password' python3 ../tools/slad_wydanie.py \
  --repo https://github.com/<user>/<repo> \
  --version 1.0 \
  file1.zip file2.tar.gz
```

Output: the trace CID plus `WERYFIKACJA.md` with hashes and instructions
for your users.

### Own root by default

By default the release trace starts **your own tree** — a root signed with
**your** key. Nothing is attached to anyone else's history.

The tool never looks for, and never reuses, another person's genesis anchor.
Attaching to a shared tree requires an explicit decision:

```bash
--root <CID>      # attach under a specific root you trust and mean to join
```

If you do not pass `--root`, you get your own root. That is the recommended
default.

### Preview without publishing

```bash
python3 tools/slad_wydanie.py --repo <url> --version 1.0 --dry-run file.zip
```

## Verify (for your users)

```bash
sha256sum file.zip                # compare with WERYFIKACJA.md
ipfs cat <CID>                    # fetch the trace
```

```python
import json, sys
sys.path.insert(0, 'tools')
import slad_protokolu as S
S.weryfikuj_podpis(json.load(open('slad-<cid>.json')))
# no exception raised = signature valid
```

## What it does and does not do

**Does:** proves that a downloaded file is byte-for-byte identical to the
one the author signed — even if it came from a mirror or a third party.

**Does not:** judge whether the software is safe, correct or useful.
It proves origin, not quality.

**Does not:** protect against malware. A signature proves *who* published a
file, not that the file is harmless. Verify software the way you verify any
unknown program.

## Limitations

- Requires a local IPFS node — there is no hosted version.
- The CID is computed by the node, not by the script.
- Publishing reveals your IP address (the key is unlinked, the transport is not).
- Proves the origin of a release, not ownership of the code.

## Example

[UNI-CNC-PRO-demo](https://github.com/czerwoney/UNI-CNC-PRO-demo) —
a signed release with `WERYFIKACJA.md`.

## Protocol

- Overview: https://scifilabx.org/slad.php
- Project site: https://scifilabx.org

## Support

SLAD is free and MIT-licensed. There is no paid tier, no token and no
company behind it. If it saved you time, you can leave a voluntary tip —
no account, no subscription, nothing to sign up for:

- Bitcoin: `bc1qrsm3kfq6yztxzp54shsruyjvrvf67sukvt869x`
- Solana: `DhnvhUgD2ZsEJSCrZ4ZhTTX3XKsStC4g81bTSoLLJ2S3`

Tips are voluntary, are not payment for services, and are non-refundable.
They are not tax-deductible. Nothing changes if you never send anything.

## Licence

MIT — see [LICENSE](LICENSE).
