# Quick Audit Linux

Uma ferramenta em Python para facilitar a vida de administradores de sistemas Linux, o **Quick Audit Linux** permite o monitoramento e diagnóstico de uma ou múltiplas máquinas virtuais (VMs) em tempo real através de conexões SSH.

<img width="1920" height="1036" alt="image" src="https://github.com/user-attachments/assets/3a6b5e1a-8c41-4125-95ee-c507f0b5fde5" />


![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-blueviolet)
![Paramiko](https://img.shields.io/badge/SSH-Paramiko-success)
![Status](https://img.shields.io/badge/status-active-success.svg)

## Objetivos
A ferramenta foi desenhada para atuar como um "canivete suíço" de monitoramento rápido sem a necessidade de instalar nenhum agente Zabbix ou Prometheus nas máquinas-alvo. 
Com apenas uma conexão SSH transparente aos servidores, os dados de Hardware, Rede e Segurança são plotados dinamicamente em abas escaláveis na interface visual!

**Aviso Legal:** O design do app foca inteiramente no conceito **Read-Only** (verificação passiva), minimizando quaisquer riscos com configurações acidentais nas VMs. O único comando destrutível com root embutido pelo app refere-se ao sincronizador de relógio (Time Sync).

---

## Principais Funcionalidades

### 1. Dashboard em Tempo Real (Matplotlib)
* Coleta por meio de *streams* em background (`/proc/stat`, `free`, `df`).
* Gráfico renderizado dinamicamente apresentando consumo em **% de CPU, RAM e Disco** atualizados a cada 2 segundos.
* Inclusão calculada e estática do **Uptime** do servidor.

### 2. Ferramentas de Rede e Diagnósticos
* Extração profunda da configuração da Interface e verificação automática de métodos Estáticos vs DHCP (via `nmcli` ou rotas).
* Mapeamento dos **Servidores DNS** contidos no `/etc/resolv.conf`.
* Testes de ICMP (Ping) calculando latência (RTT) e perda de pacotes comunicando com o **Gateway nativo** da rede e com a internet aberta (Google DNS - `8.8.8.8`).

### 3. Auditoria Básica de Segurança (Security Audit)
Analisa as principais vulnerabilidades operacionais e provê os relatórios ativamente num log isolado:
* **Disk Analyzer:** Verifica proativamente quais são as **3 partições em disco mais lotadas** da sua infra.
* **Gestão de Logs:** Audita o tamanho bruto da pasta nativa `/var/log` para verificar se os Logs do SO estão saindo de controle e averígua o timer do serviço **Logrotate**.
* **Monitor de Portas de Rede:** Identifica as 5 principais portas abertas na rede do Kernel associadas ao PID dos seus processos-alvo (Extraídos formatados sobre o pacote `ss` ou `netstat` do utilitário `iproute2`).
* Lista ativamente Nível de Usuários Comuns (evitando intrusões `uid>=1000`).
* Confere se as **regras do Firewall** encontram-se expostas (UFW/Iptables).
* Lê o **Timezone** ativo e analisa se a VM está devidamente atrelada ao relógio uníssono (NTP/Network Time Protocol).

### 4. Sincronização de Relógio One-Click
* Ao lado da Auditoria, um botão funcional "Sincronizar Hora com Hospedeiro". Ele adquire a tag de tempo atual da sua máquina host com Windows, configura a VM para America/Sao_Paulo (GMT -3) via sistema sudo escalado, re-atualiza ativamente o relógio base do SO Linux local via Data Timestamp e reinicia o `timedatectl`.

### 5. Suporte Multitarefas (Multi-VM)
* Implementação sofisticada baseada em threads Python desacopladas. Crie **infinitas instâncias (Abas)** com cliques na UI. As métricas e gráficos das máquinas virtuais nunca irão misturar inputs nos buffers de renderização. Suas abas auto-nomeiam as flags interativas com as credenciais do novo Host ao se conectar!

---

## Stack Tecnológica Envolvida
* **Linguagem**: `Python`
* **GUI / Frontend**: `customtkinter`
* **Biblioteca de Conexão**: `paramiko` 
* **Mapeamento de Gráficos**: `matplotlib` 

---

## Como Executar Localmente

### Pré-requisitos
* Ter o Python instalado.
* Uma ou mais Máquinas Virtuais Linux com protocolo SSH ativado (porta 22 ou customizada). 

### Instalação

Abra o terminal na pasta raiz do seu projeto recém extraído:

1. **Instale as dependências nativas com o Pip**:
   ```powershell
   pip install -r requirements.txt
   ```

2. **Inicie a Ferramenta Gráfica**:
   ```powershell
   python main.py
   ```

---
