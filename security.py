import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class FinTechEncryptionManager:
    """
    Gestor de seguridad para FinTech Solutions.
    Implementa cifrado simétrico AES-256 en modo GCM para garantizar
    confidencialidad e integridad de los datos financieros.
    """
    def __init__(self, master_key: bytes = None):
        # Si no se provee una llave maestra, se genera una de 256 bits (32 bytes)
        # En un entorno real, esta llave debe almacenarse en un gestor seguro (ej. AWS KMS, HashiCorp Vault)
        self.master_key = master_key if master_key else AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_data(self, sensitive_data: str) -> dict:
        """
        Cifra datos financieros sensibles (ej. números de tarjetas o cuentas).
        Retorna un diccionario con el Nonce y el texto cifrado (ciphertext).
        """
        # Generar un Nonce (Number used once) único de 12 bytes recomendado para GCM
        nonce = os.urandom(12)
        
        # Convertir el string a bytes
        data_bytes = sensitive_data.encode('utf-8')
        
        # Cifrar los datos
        ciphertext = self.aesgcm.encrypt(nonce, data_bytes, associated_data=None)
        
        return {
            "nonce": nonce,
            "ciphertext": ciphertext
        }

    def decrypt_data(self, nonce: bytes, ciphertext: bytes) -> str:
        """
        Descifra los datos utilizando el mismo Nonce y la llave maestra.
        Verifica automáticamente la integridad de los datos.
        """
        try:
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError("Error de descifrado: Los datos fueron corrompidos o la llave es inválida.") from e

# ==========================================
# 3. Pruebas y Validación (Ejemplo de uso)
# ==========================================
if __name__ == "__main__":
    print("--- INICIANDO PRUEBAS DE SEGURIDAD FINTECH SOLUTIONS ---\n")
    
    # Instanciar el gestor
    security_manager = FinTechEncryptionManager()
    
    # Escenario: Datos financieros sensibles de clientes
    datos_financieros = [
        "Tarjeta_Credito: 4532-XXXX-XXXX-8921",
        "Cuenta_Bancaria: 10987654321",
        "Monto_Transaccion: $15,000,000 COP"
    ]
    
    for idx, dato in enumerate(datos_financieros, 1):
        print(f"[Escenario {idx}] Dato original: {dato}")
        
        # Cifrado
        encrypted = security_manager.encrypt_data(dato)
        print(f" -> Nonce (Hex): {encrypted['nonce'].hex()}")
        print(f" -> Cifrado (Hex): {encrypted['ciphertext'].hex()}")
        
        # Descifrado
        decrypted = security_manager.decrypt_data(encrypted['nonce'], encrypted['ciphertext'])
        print(f" -> Descifrado exitoso: {decrypted}\n")
        
    print("--- PRUEBAS FINALIZADAS EXITOSAMENTE ---")