import logging

def send_email(
    to: str,
    subject: str,
    body: str
):
    """
    Envia um email simples.
    Parâmetros:
    - to: Destinatário do email
    - subject: Assunto do email
    - body: Corpo do email
    """
    logging.info(f"Enviando email para {to} com assunto '{subject}' e corpo: {body}")
