# Forthres Security & Exploit Intelligence Engine

[![Rust](https://img.shields.io/badge/rust-1.84%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Motor enterprise de auditoria, inferencia de exploits e validacao ofensiva para contratos EVM (Ethereum, BSC, Arbitrum)**  
> O core combina analise estatica, simulacao RPC, execucao simbolica e validacao por fork para responder nao apenas se existe risco, mas se existe **exploitabilidade operacional real**.

---

## Visao Geral

O **Forthres** nao deve ser entendido como "mais um scanner".

Ele e um **motor de decisao ofensiva**, projetado para responder:

> **"Essa superficie e exploravel no mundo real, com impacto economico e caminho de execucao plausivel?"**

Para isso, ele combina:

- analise estrutural de bytecode
- simulacao RPC com `eth_call`
- execucao simbolica e aproximacao de estado
- inferencia de exploit paths
- analise economica e contexto MEV
- validacao opcional via fork real

---

## Capacidades

| Modulo | Descricao | Resultado |
|--------|----------|----------|
| **Bytecode Intelligence** | Deteccao de padroes perigosos como `DELEGATECALL`, `SELFDESTRUCT` e `CALLCODE` | Flags + severity |
| **Selector Intelligence** | Extracao e matching de seletores contra assinaturas perigosas | Surface mapping |
| **RPC Simulation Layer** | Execucao de chamadas reais via `eth_call` | Behavior inference |
| **State Approximation Engine** | Modelagem parcial de storage, permissoes e fluxo | Contexto de execucao |
| **Offensive Engine** | Geracao de exploit paths e valor economico esperado | Probabilidade + EV |
| **Fork Validation** | Reproducao em fork controlado | Confirmacao operacional |

---

## Modelo de Confianca

| Score | Classificacao | Interpretacao |
|------|-------------|--------------|
| 80-100 | CRITICAL | Exploit altamente provavel ou confirmado |
| 60-79  | HIGH     | Evidencia forte de exploracao |
| 40-59  | MEDIUM   | Exploracao condicional ou dependente de contexto |
| 20-39  | LOW      | Baixa exposicao |
| 0-19   | INFO     | Sem evidencia relevante |

---

## Arquitetura

```text
                +------------------------------+
                |     forthres core (Rust)     |
                +------------------------------+
                | bytecode | selectors | fork  |
                | state    | exploit   | mev   |
                | scoring  | reporting | diag  |
                +------------------------------+
                               |
                       JSON event stream
                               |
                +------------------------------+
                |   API / CLI / SDK layer      |
                | Node transport + UX surface  |
                +------------------------------+
```

---

## Estrutura do Projeto

```text
ghost-scanner/
├── reports/
├── scripts/
├── src/
│   ├── analysis/
│   ├── bin/
│   │   ├── exploit_executor.rs
│   │   ├── forthres-scan.rs
│   │   └── forthres-verify.rs
│   ├── bytecode/
│   ├── config/
│   ├── core/
│   ├── forensics/
│   ├── orchestration/
│   ├── reporting/
│   ├── service/
│   └── verify/
```

Nota:
- o diretório ainda se chama `ghost-scanner` no repositório
- o produto e o branding operacional documentados aqui passam a ser **Forthres**

---

## Pipeline de Execucao

```text
1. Fetch bytecode via RPC
2. Decode e opcode scan
3. Extract selectors
4. Simulate via eth_call
5. Build state approximation
6. Generate exploit hypotheses
7. Score probability + economic value
8. Optionally validate in fork
9. Emit final report + machine events
```

---

## Produto Distribuido via NPM

O produto que o cliente usa no dia a dia nao e o binario Rust isolado.

O produto distribuido para operacao, CI, onboarding de cliente e uso comercial e:

```bash
npm install forthress-scan
```

ou, sem instalacao global:

```bash
npx forthress-scan scan <contract> --chain ethereum --mode deep --api-key hk_...
```

Esse pacote e a **superficie enterprise oficial do produto**.

Ele entrega:

- o comando `npx forthress-scan`
- o fluxo visual premium de terminal
- o contrato de logs e eventos em tempo real
- o cliente SDK para automacao
- a integracao com API, persistencia e replay operacional

O core Rust continua sendo o motor de execucao, mas o **produto consumido** por cliente, time interno e pipeline e `forthress-scan`.

---

## O Que `npm install forthress-scan` Faz

Quando voce executa:

```bash
npm install forthress-scan
```

isso **nao instala o core Rust diretamente como binario solto do sistema**.

Na pratica, essa instalacao disponibiliza a **camada enterprise de distribuicao e operacao**:

- o pacote Node/CLI que o time usa com `npx forthress-scan`
- o cliente SDK para integracao com CI, automacao e pipelines
- a interface operacional que conversa com o backend e com o motor de scanning
- o formato de logs, eventos e relatorios consumidos por times de seguranca e plataforma

Em outras palavras:

- `ghost-scanner`/core Rust e o motor de execucao
- `forthress-scan` e a superficie distribuida para uso enterprise

O fluxo esperado e:

```text
npx forthress-scan
  -> chama a camada de API/stream
  -> essa camada aciona o core de analise
  -> o operador recebe logs em tempo real
  -> o processo produz JSON, resumo humano e relatorio persistido
```

---

## Experiencia Real do Produto no Terminal

O comportamento esperado do produto nao e um output cru de engenharia.

O `forthress-scan` foi desenhado para entregar uma experiencia de operacao premium, em camadas:

1. identidade visual e contexto do scan
2. logs progressivos por fase
3. evidencias resumidas sem despejar ruido bruto
4. veredito final com score, confidence e recomendacao

Um scan real se parece com isso:

```text
   __ _______  ______  ___  ___
  / // / __/ |/_/ __ \/ _ \/ _ |
 / _  / _/_>  </ /_/ / , _/ __ |
/_//_/___/_/|_|\____/_/|_/_/ |_|

  Security  •  Blockchain  •  Determinism

╭──────────────────────────────────────────────────────────╮
│                                                          │
│  TARGET      0xdAC17F958D2ee523a2206206994597C13D831ec7  │
│  CHAIN       ethereum                                    │
│  MODE        DEEP                                        │
│  FORK        AUTO                                        │
│  BEACON      ENABLED                                     │
│  API         forthres-api.app                            │
│                                                          │
╰──────────────────────────────────────────────────────────╯

  ∙  Starting Rust scanner for 0xdAC17F958D2ee523a2206206994597C13D831ec7 on ethereum
  ∙  Mode=DEEP Beacon=true Fork=AUTO
  ⬢  Fetched bytecode from live RPC
⬢ Forthres bytecode intake
  ⚠  Forthres bytecode summary: sstore medium=23 · call low=6
⬢ Forthres opcode intelligence
  ⬢  Extracted 37 selectors from live bytecode
  ⚠  Forthres selector watchlist: transferOwnership(address) - Ownership transfer
⬢ Forthres selector intelligence
  ∙  No EIP-1967 implementation or beacon slot detected
⬢ Forthres control-surface analysis
  ⚡  Beacon: 2/5 succeeded · 3 reverted
⬢ Forthres replay engine
  ◇  Fork validation confirmed a reachable unauthorized execution path
⬢ Forthres fork validation
  ∙  Offensive analysis complete — no viable exploit paths detected
⬢ Forthres offensive engine
  ⬢  Scan complete. Severity=INFO Kind=GENERIC_CONTRACT Confidence=35/100 | Offensive: P=0.00% EV=-0.0000 ETH
  ⬢  Report persisted to database with id 1bca00d0-77f1-4e17-9c04-bd89bd336925

  ═══════════════════════════════════════════════════════════
                     SCAN COMPLETE
  ═══════════════════════════════════════════════════════════
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╭────────────────────────────────────────╮
│     ✓  FORTHRESS SCAN COMPLETE         │
│     Status        INFO                 │
│     Confidence    35/100               │
│     Paths Found   0                    │
│     MEV Opportunities 0                │
╰────────────────────────────────────────╯
```

Esse output e parte do produto.

Ele existe para:

- reduzir tempo de leitura em incidente
- orientar analista sem exigir leitura de JSON cru
- transformar a execucao tecnica em narrativa operacional
- mostrar para cliente e time interno onde a analise ganhou ou perdeu confianca

---

## O Que os Logs Fazem

Os logs do Forthres nao sao apenas "prints de terminal".

Eles funcionam como uma **trilha operacional de auditoria** para:

- mostrar em que fase o scan esta
- indicar quais sinais tecnicos foram encontrados
- separar ruido de evidencias relevantes
- informar fallback de execucao, por exemplo RPC-only quando fork falha
- permitir streaming para UI, API, CI e dashboards

No produto `forthress-scan`, os logs cumprem quatro papeis ao mesmo tempo:

- **telemetria de progresso**
  mostra exatamente em qual fase o scan esta
- **compressao de evidencias**
  resume bytecode, selectors, beacon e fork sem inundar o operador
- **sinal para automacao**
  permite que CI, backend ou dashboard reajam a eventos estruturados
- **auditabilidade**
  deixa uma trilha reproduzivel do que foi observado e decidido

### Modelo de logs

O sistema trabalha com eventos como:

- `step`
  representa inicio, conclusao ou erro de uma fase
- `log`
  representa observacoes operacionais, findings intermediarios e hints
- `error`
  representa falha bloqueante ou degradacao importante
- `complete`
  representa a entrega do relatorio final consolidado

### Modelo estrutural de eventos

```json
{"type":"step","id":"bytecode","label":"Fetch & decode bytecode","status":"running"}
{"type":"log","level":"success","message":"Fetched bytecode from live RPC","ts":"2026-05-01T12:00:00Z"}
{"type":"log","level":"warn","message":"Dangerous selector match: 0xf2fde38b","ts":"2026-05-01T12:00:01Z"}
{"type":"step","id":"fork","label":"Anvil fork execution","status":"done"}
{"type":"complete","report":{"severity":"HIGH","confidenceScore":84}}
```

### Como ler o output enterprise do `forthress-scan`

- bloco de banner
  identifica produto, posicionamento e consistencia de marca
- card inicial
  fixa target, chain, mode, fork, beacon e endpoint de API
- linhas de progresso
  mostram o pipeline vivo sem esconder degradacoes
- summaries intermediarios
  condensam achados de bytecode e selectors em linguagem operacional
- bloco final
  fecha o scan com severidade, confidence, valor economico e recomendacao

### Leitura enterprise dos logs

- `running`
  a fase foi iniciada e esta em execucao
- `done`
  a fase terminou sem bloqueio
- `warn`
  ha evidencia relevante, mas ainda nao conclusiva
- `error`
  houve falha operacional ou bloqueio de analise
- `complete`
  o scan fechou o ciclo e entregou um artefato final confiavel

Esses logs sao importantes porque permitem:

- observabilidade para times SOC e AppSec
- integracao com pipelines de release gate
- trilha de troubleshooting quando um scan degrada
- serializacao limpa para armazenamento e replay

---

## Integracao Node.js

O motor opera como **stream JSON orientado a eventos**:

```js
const scanner = spawn("./forthres-core", [...]);

scanner.stdout.on("data", (data) => {
  const lines = data.toString().split("\n");
  for (const line of lines) {
    if (!line) continue;
    const event = JSON.parse(line);
    sendToClient(event);
  }
});
```

Esse modelo e o que viabiliza:

- UX em tempo real no CLI
- forwarding para frontend
- persistencia de auditoria
- integracao com SIEM ou pipelines internos

---

## Offensive Engine

O bloco ofensivo e o diferencial central do Forthres:

- **Path Finder**: constroi CFG e restricoes
- **Symbolic Executor**: explora caminhos viaveis
- **Probability Engine**: estima chance de sucesso
- **Economic Model**: calcula valor drenavel
- **MEV Layer**: identifica front-run, back-run e sandwich
- **Feedback Loop**: mutacao adaptativa de cenarios

### Exemplo de saida

```json
{
  "exploitationProbability": 0.87,
  "riskAdjustedValue": 14.2,
  "exploitPaths": [
    {
      "entrySelector": "0xf2fde38b",
      "probability": 0.94,
      "economicValueEth": 16.0
    }
  ]
}
```

---

## Relatorios

```text
reports/
├── *.json
└── *.md
```

Incluem:

- severity + confidence
- evidencias
- value flow
- exploit paths
- contexto MEV
- recomendacoes operacionais

---

## Testes

```bash
cargo test
```

Cobertura esperada:

- parsing de bytecode
- engine probabilistica
- geracao de paths
- feedback loop

---

## Troubleshooting

| Problema | Solucao |
|--------|--------|
| Bytecode nao encontrado | Verifique RPC, chain e endereco |
| RPC mismatch | Ajuste `SCANNER_CHAIN_ID` |
| Fork indisponivel | Verifique `ANVIL_RPC_URL` ou o provedor de fork |
| Erro de transacao tipada | Use `provider.call()` ou normalize a request |

---

## Stack Tecnica

- Rust para performance e safety
- ethers-rs para RPC e EVM
- tokio para runtime async
- serde para serializacao
- reqwest para fallback RPC
- sha3 para selectors
- tracing para observabilidade

---

## Aviso

Uso restrito a:

- auditoria autorizada
- pesquisa de seguranca
- validacao defensiva

Exploracao sem permissao e ilegal.

---

## Licenca

MIT
