# MINI-HONEYPOT
meus projetos 

 Mini Honeypot

Esse é um projeto simples que eu fiz pra começar a entender melhor como funciona a parte de escuta de conexões e captura de dados em redes. 
É tipo um honeypot básico feito em Python, que registra IP, porta e o que for enviado pra ele.

É bem simples, mas funcional.


 O que ele faz

- Escuta conexões na porta 8080 (dá pra mudar com `--port`)
- Registra o IP de quem tentou se conectar, mesmo que não mande nada (tipo um port scan)
- Guarda o texto enviado no log, numa linha só e "escapado" (ninguém consegue forjar linhas falsas no log)
- Funciona com telnet, netcat ou até navegadores (o navegador não vai mostrar uma página bonita, porque a resposta não é HTTP)
- Cria os logs em uma pastinha automática (`logs/`, do lado do script), com rotação pra não encher o disco
- Tem timeout e limite de conexões simultâneas, pra não travar se alguém tentar derrubar


 Por que eu fiz isso?

Tô estudando cibersegurança e queria colocar a mão no código. Sempre vi sobre honeypots, mas nunca tinha feito um. 
Esse projeto é meu jeito de começar a explorar o lado da coleta de informações (passiva, no caso).


 Como rodar

1. Tenha Python 3 instalado (usei a versão 3.14). Não precisa instalar nenhuma biblioteca.
2. Clona o repositório:
   ```bash
   git clone https://github.com/Leonard0MF/mini-honeypot
   cd mini-honeypot
   ```
3. Roda:
   ```bash
   python3 honeypot.py
   # ou com opções:
   python3 honeypot.py --port 2222 --timeout 5 --max-conns 50
   ```
   Portas abaixo de 1024 (tipo a 80) precisam de root no Linux.
4. Testa de outro terminal:
   ```bash
   printf 'oi\n' | nc localhost 8080
   ```

O log fica em `logs/connections.log`, num formato assim:

```
[2026-11-24T12:00:00Z] Conexão de 127.0.0.1:54321 -> oi\n
```

Isso aqui é só pra estudo. Não use isso exposto na internet sem proteção, e sempre com responsabilidade.

Feito por mim
Leonardo — 17 anos, estudando programação e cibersegurança.
