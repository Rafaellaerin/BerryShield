# @berryshield/browser

```ts
import { BerryShield } from "@berryshield/browser";

const shield = new BerryShield({
  siteKey: "bs_public_xxx",
  endpoint: "https://shield.example.com",
  wasmProbeUrl: "https://shield.example.com/probe.wasm"
});

const token = await shield.execute("login");
```

Send `token` to your application backend. Your backend must call BerryShield
`POST /v1/siteverify` with the private site secret before performing the sensitive action.

The SDK collects aggregate browser and interaction signals. It does **not** capture
keystroke content, pointer coordinates, form contents, clipboard data, microphone,
camera, geolocation, or raw canvas/audio fingerprints.
