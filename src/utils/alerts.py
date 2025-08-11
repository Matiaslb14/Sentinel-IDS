import requests
import html
import datetime
import os

class TelegramAlerter:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.log_path = os.path.join("logs", "sentinel.log")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def alert(self, title, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {title} - {message}"

        # Mostrar en consola
        print(log_line)

        # Guardar en archivo
        with open(self.log_path, "a") as log_file:
            log_file.write(log_line + "\n")

        # Si no hay Telegram configurado, salir aquí
        if not self.bot_token or not self.chat_id:
            return

        # Enviar a Telegram
        text = f"*{html.escape(title)}*\n{html.escape(message)}"
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            requests.post(url, json={
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown"
            }, timeout=5)
        except Exception:
            pass

