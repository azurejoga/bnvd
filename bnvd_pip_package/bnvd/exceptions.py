class BNVDAPIError(Exception):
    """Erro retornado pela API do BNVD."""
    def __init__(self, message, code=None):
        super().__init__(f"BNVD API Error {code}: {message}")
        self.message = message
        self.code = code


class BNVDConnectionError(Exception):
    """Erro de conexão com a API do BNVD."""
    def __init__(self, message):
        super().__init__(f"BNVD Connection Error: {message}")
        self.message = message


class BNVDInvalidResponse(Exception):
    """Resposta inválida da API do BNVD."""
    def __init__(self, message):
        super().__init__(f"BNVD Invalid Response: {message}")
        self.message = message
