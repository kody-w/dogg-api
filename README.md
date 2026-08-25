# dogg-api — the DOGG network as free static JSON endpoints

The chains at [kody-w/dogg](https://github.com/kody-w/dogg) are the verifiable record;
these files are the convenience face. Rebuilt every 30 minutes by CI. No keys, no rate
plans — it's static JSON on GitHub.

- **Latest world state:** `api/latest.json`
- **Full time series per source** (BTC spot, FX, fees, mempool, quakes, ISS, Kp, grid
  carbon, HN, prediction markets, block height, market cap): `api/series/<source>.json`
- **Directory:** `api/index.json`

Raw base: `https://raw.githubusercontent.com/kody-w/dogg-api/main/`

Every row carries the frame hash it came from — any value can be audited back to the
append-only chain that recorded it. That's the difference between this and a mirror of
an API: the history is verifiable, not asserted.
