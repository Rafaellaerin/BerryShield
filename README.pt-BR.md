# BerryShield — visão geral em PT-BR

BerryShield é uma plataforma anti-bot/CAPTCHA adaptativa, aberta e auto-hospedável. O projeto combina sinais do navegador, contexto derivado pelo servidor, reputação de IP, pontuação de risco, tokens de prova de uso único, proof-of-work e um desafio interativo acessível.

A implementação é dividida em **Go** (gateway), **Rust** (risk engine opcional), **Python** (reputação de IP), **TypeScript/JavaScript** (SDK do navegador) e **WebAssembly** (probe de execução no cliente).

O fluxo é: o SDK solicita uma decisão em `/v1/challenge`; o gateway combina política, rate limit, reputação e score; usuários de baixo risco recebem token invisível, risco médio recebe PoW, risco mais alto recebe press-and-hold acessível + PoW leve e risco crítico pode ser bloqueado. O token final só vale depois de verificado pelo backend em `/v1/siteverify` e é consumido na primeira verificação.

Os HARs enviados foram analisados **estruturalmente**, sem copiar cookies, tokens ou payloads opacos. Os padrões observados em AWS WAF CAPTCHA/Challenge, GeeTest, hCaptcha, reCAPTCHA e Turnstile estão documentados em [`docs/research/HAR_OBSERVATIONS.md`](docs/research/HAR_OBSERVATIONS.md).

O diretório `redteam/` testa apenas o **BerryShield**. Técnicas conhecidas de automação, replay, stealth e inconsistência de fingerprint são modeladas como cenários defensivos; o repositório não inclui um bypass operacional para Cloudflare, reCAPTCHA ou hCaptcha.

Para começar, veja o [`README.md`](README.md) e [`docs/INTEGRATION.md`](docs/INTEGRATION.md).
