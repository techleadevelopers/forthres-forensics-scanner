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
│   │   ├── hexora-scan.rs
│   │   └── hexora-verify.rs
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

## Instalacao Enterprise via NPM

Quando voce executa:

```bash
npm install forthress-scan
```

isso **nao instala o core Rust diretamente como binario solto do sistema**.

Na pratica, essa instalacao serve para disponibilizar a **camada enterprise de distribuicao e operacao**:

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

## O Que os Logs Fazem

Os logs do Forthres nao sao apenas "prints de terminal".

Eles funcionam como uma **trilha operacional de auditoria** para:

- mostrar em que fase o scan esta
- indicar quais sinais tecnicos foram encontrados
- separar ruido de evidencias relevantes
- informar fallback de execucao, por exemplo RPC-only quando fork falha
- permitir streaming para UI, API, CI e dashboards

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

### Exemplo conceitual

```json
{"type":"step","id":"bytecode","label":"Fetch & decode bytecode","status":"running"}
{"type":"log","level":"success","message":"Fetched bytecode from live RPC","ts":"2026-05-01T12:00:00Z"}
{"type":"log","level":"warn","message":"Dangerous selector match: 0xf2fde38b","ts":"2026-05-01T12:00:01Z"}
{"type":"step","id":"fork","label":"Anvil fork execution","status":"done"}
{"type":"complete","report":{"severity":"HIGH","confidenceScore":84}}
```

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
