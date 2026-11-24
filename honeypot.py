import argparse
import logging
import os
import socket
import threading
import time
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_PAYLOAD = 4096
BANNER = b"Obrigado pela conexao!\n"

logger = logging.getLogger("honeypot")


def setup_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    fmt = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%dT%H:%M:%SZ")
    fmt.converter = time.gmtime  # horários em UTC

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "connections.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)

    console = logging.StreamHandler()
    console.setFormatter(fmt)

    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console)


def sanitize(data):
    """Transforma os bytes recebidos em uma única linha segura (sem \\n nem códigos ANSI)."""
    text = data.decode("utf-8", errors="backslashreplace")
    out = []
    for ch in text:
        if ch == "\\" or ch.isprintable():
            out.append(ch)
        else:
            out.append(ch.encode("unicode_escape").decode("ascii"))
    return "".join(out)


def read_payload(conn):
    """Lê até MAX_PAYLOAD bytes, até o cliente fechar ou até estourar o timeout."""
    chunks = []
    total = 0
    try:
        while total < MAX_PAYLOAD:
            chunk = conn.recv(MAX_PAYLOAD - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            # Se o cliente parou de mandar (ex.: uma linha no telnet), não espera o timeout todo
            conn.settimeout(1.0)
    except socket.timeout:
        pass
    return b"".join(chunks)


def handle_client(conn, addr, timeout, slots):
    try:
        conn.settimeout(timeout)
        data = read_payload(conn)
        payload = sanitize(data) if data else "<vazio>"
        logger.info("Conexão de %s:%s -> %s", addr[0], addr[1], payload)
        try:
            conn.sendall(BANNER)
        except OSError:
            pass
    except Exception as e:
        logger.info("Erro com %s:%s -> %s", addr[0], addr[1], e)
    finally:
        conn.close()
        slots.release()


def start_honeypot(host, port, timeout, max_conns):
    slots = threading.BoundedSemaphore(max_conns)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(128)
    logger.info("Honeypot escutando em %s:%s", host, port)

    try:
        while True:
            try:
                conn, addr = server.accept()
            except OSError as e:
                logger.info("Erro no accept: %s", e)
                time.sleep(0.5)
                continue

            if not slots.acquire(blocking=False):
                logger.info("Limite de conexões atingido, recusando %s:%s", addr[0], addr[1])
                conn.close()
                continue

            threading.Thread(
                target=handle_client,
                args=(conn, addr, timeout, slots),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        logger.info("Encerrando honeypot.")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description="Mini honeypot TCP")
    parser.add_argument("--host", default="0.0.0.0", help="endereço para escutar (padrão: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="porta (padrão: 8080)")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout por conexão em segundos (padrão: 10)")
    parser.add_argument("--max-conns", type=int, default=100, help="máximo de conexões simultâneas (padrão: 100)")
    parser.add_argument("--log-dir", default=os.path.join(BASE_DIR, "logs"), help="pasta dos logs")
    args = parser.parse_args()

    setup_logging(args.log_dir)
    start_honeypot(args.host, args.port, args.timeout, args.max_conns)


if __name__ == "__main__":
    main()
