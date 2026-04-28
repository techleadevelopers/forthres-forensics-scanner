# SafeContract — EVM Security & Exploit Intelligence Engine

> **Motor avançado de auditoria e inferência de exploits para contratos EVM (Ethereum, BSC, Arbitrum)**  
> Combina análise estática, simulação RPC, execução simbólica e validação por fork para detectar vulnerabilidades com **contexto econômico real (MEV-aware)**.

[![Rust](https://img.shields.io/badge/rust-1.84%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

##  Visão Geral

O **Ghost Scanner** não é apenas um scanner de vulnerabilidades.

Ele é um **motor de inferência de exploração**, projetado para responder:

> **“Isso é explorável no mundo real?”**

Para isso, ele combina múltiplas camadas:

-  **Análise estrutural (bytecode)**
-  **Simulação RPC (eth_call)**
-  **Execução simbólica + modelagem de estado**
-  **Análise ofensiva (exploit paths + MEV)**
-  **Validação opcional via fork (Anvil/Tenderly)**

---

##  Capacidades

| Módulo | Descrição | Resultado |
|--------|----------|----------|
| **Bytecode Intelligence** | Detecção de padrões perigosos (DELEGATECALL, SELFDESTRUCT, CALLCODE) | Flags + severity |
| **Selector Intelligence** | Extração + matching com base de assinaturas | Surface mapping |
| **RPC Simulation Layer** | Execução de chamadas reais via `eth_call` | Behavior inference |
| **State Approximation Engine** | Modelagem parcial de storage e fluxos | Contexto de execução |
| **Offensive Engine** | Geração de caminhos de exploit e análise econômica | Probabilidade + EV |
| **Fork Validation (opcional)** | Execução em fork real | Confirmação de exploit |

---

##  Modelo de Confiança

| Score | Classificação | Interpretação |
|------|-------------|--------------|
| 80–100 | 🔴 CRITICAL | Exploit altamente provável / confirmado |
| 60–79  | 🟠 HIGH     | Forte evidência de exploração |
| 40–59  | 🟡 MEDIUM   | Possível exploração (condicional) |
| 20–39  | 🔵 LOW      | Baixo risco |
| 0–19   | ⚪ INFO     | Sem evidência relevante |

---

##  Arquitetura

```text
                ┌────────────────────────────┐
                │     ghost-scanner (Rust)   │
                ├────────────────────────────┤
                │ scanner.rs (orchestrator)  │
                ├──────────────┬─────────────┤
                │ bytecode.rs  │ selectors   │
                │ forensics.rs │ fork layer  │
                │ offensive/   │ exploit AI  │
                │ reporter.rs  │ output      │
                └──────┬───────┴─────────────┘
                       │
                JSON (stdout stream)
                       │
        ┌──────────────▼──────────────┐
        │        API Server (Node)    │
        │  spawn + stream processing │
        └────────────────────────────┘
```

---

##  Estrutura do Projeto

```text
ghost-scanner/
├── reports/
├── scripts/
├── src/
│   ├── bin/
│   │   └── ghost-scanner.rs
│   ├── offensive/
│   │   ├── path_finder.rs
│   │   ├── probability_engine.rs
│   │   ├── economic_impact.rs
│   │   ├── mev_integration.rs
│   │   ├── feedback_loop.rs
│   │   └── symbolic_executor.rs
│   ├── bytecode.rs
│   ├── config.rs
│   ├── forensics.rs
│   ├── load_balancer.rs
│   ├── reporter.rs
│   └── scanner.rs
```

---

##  Pipeline de Execução

```text
1. Fetch bytecode (RPC)
2. Decode + opcode scan
3. Extract selectors
4. Simulate via eth_call
5. Build state approximation
6. Generate exploit hypotheses
7. Score (probability + EV)
8. (Opcional) validar via fork
9. Gerar relatório final
```

---

##  Offensive Engine (diferencial real)

O módulo `offensive/` transforma análise em **exploitability real**:

- **Path Finder** → constrói CFG + condições
- **Symbolic Executor** → explora caminhos possíveis
- **Monte Carlo Engine** → estima probabilidade
- **Economic Model** → calcula valor drenável
- **MEV Layer** → identifica:
  - frontrun
  - backrun
  - sandwich
- **Feedback Loop** → mutação adaptativa de cenários

### Exemplo de saída:

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

## 📡 Integração (Node.js)

O scanner opera como **stream JSON (event-driven)**:

```js
const scanner = spawn('./ghost-scanner', [...]);

scanner.stdout.on('data', (data) => {
  const lines = data.toString().split('\n');
  for (const line of lines) {
    if (!line) continue;
    const event = JSON.parse(line);
    sendToClient(event);
  }
});
```

---

##  Relatórios

```text
reports/
├── *.json   ← machine-readable
└── *.md     ← human-readable
```

Inclui:

- severity + confidence
- evidências
- value flow
- exploit paths
- análise MEV
- recomendações

---

## 🧪 Testes

```bash
cargo test
```

Cobertura inclui:

- parsing de bytecode
- engine probabilística
- geração de paths
- feedback loop

---

## 🔧 Troubleshooting

| Problema | Solução |
|--------|--------|
| Bytecode não encontrado | Verifique rede + endereço |
| RPC mismatch | Ajuste `SCANNER_CHAIN_ID` |
| Fork não funciona | Verifique `ANVIL_RPC_URL` |
| Erro TypedTransaction | Use `provider.call()` |

---

## 📌 Stack Técnica

- **Rust** → performance + safety
- **ethers-rs** → RPC / EVM
- **tokio** → async runtime
- **serde** → serialization
- **reqwest** → fallback RPC
- **sha3** → selectors
- **tracing** → observabilidade

---

## ⚠️ Aviso

Uso restrito a:

- auditoria autorizada
- pesquisa de segurança

Exploração sem permissão é ilegal.

---

## 📄 Licença

MIT © Ghost Scanner Contributors