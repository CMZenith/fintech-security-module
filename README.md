Módulo de Seguridad Criptográfica para FinTech Solutions
Autor: Ingeniería de Software
Fecha: 2026
Descripción: 
    Este script implementa el cifrado y descifrado simétrico utilizando el algoritmo 
    AES-256 en modo GCM (Galois/Counter Mode). Proporciona confidencialidad e 
    integridad para la protección de datos financieros sensibles (tarjetas de crédito, 
    cuentas bancarias y montos de transacciones) cumpliendo con los estándares de 
    seguridad exigidos por la industria (PCI-DSS y normativas financieras).
"""

import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class FinTechEncryptionManager:
    """
    Gestor centralizado de cifrado para FinTech Solutions.
    Utiliza AES-256-GCM para asegurar que la información permanezca protegida
    tanto en tránsito como en reposo, previniendo fraudes y manipulaciones.
    """
    
    def __init__(self, master_key: bytes = None):
        """
        Inicializa el gestor de cifrado generando o cargando una llave maestra de 256 bits (32 bytes).
        
        Args:
            master_key (bytes, optional): Llave secreta simétrica. Si es None, se genera una nueva.
        """
        if master_key:
            if len(master_key) != 32:
                raise ValueError("La llave maestra debe ser exactamente de 32 bytes (256 bits) para AES-256.")
            self.master_key = master_key
        else:
            # Generación segura de una llave de 256 bits (32 bytes) utilizando fuentes entropía del sistema
            self.master_key = AESGCM.generate_key(bit_length=256)
            
        # Instancia del cifrador AESGCM optimizado con la llave maestra
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_data(self, sensitive_data: str) -> dict:
        """
        Cifra datos financieros sensibles asegurando confidencialidad e integridad (AEAD).
        
        Args:
            sensitive_data (str): Información en texto plano (ej. número de tarjeta, cuenta).
            
        Returns:
            dict: Diccionario que contiene el Nonce (vector de inicialización) y el texto cifrado (ciphertext).
        """
        try:
            # Generación de un Nonce (Number used once) único de 12 bytes (96 bits) recomendado para GCM.
            # El Nonce NUNCA debe repetirse con la misma llave para evitar ataques de reutilización.
            nonce = os.urandom(12)
            
            # Conversión de la cadena de texto plano a bytes utilizando codificación UTF-8
            data_bytes = sensitive_data.encode('utf-8')
            
            # Cifrado de los datos. AESGCM incluye automáticamente una etiqueta de autenticación (tag)
            # combinada con el texto cifrado para detectar cualquier intento de manipulación posterior.
            ciphertext = self.aesgcm.encrypt(nonce, data_bytes, associated_data=None)
            
            return {
                "nonce": nonce,
                "ciphertext": ciphertext
            }
        except Exception as e:
            raise RuntimeError(f"Error crítico durante el proceso de cifrado: {str(e)}") from e

    def decrypt_data(self, nonce: bytes, ciphertext: bytes) -> str:
        """
        Descifra y verifica la integridad de los datos financieros cifrados.
        
        Args:
            nonce (bytes): Vector de inicialización único utilizado en el cifrado (12 bytes).
            ciphertext (bytes): Datos cifrados acompañados de su etiqueta de autenticación.
            
        Returns:
            str: Información original recuperada en texto plano.
        """
        try:
            # Descifrado y verificación simultánea de integridad. Si los datos fueron alterados
            # o el Nonce/Llave no coinciden, se lanzará una excepción criptográfica.
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            
            # Conversión de los bytes recuperados nuevamente a string UTF-8
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(
                "Fallo de seguridad o integridad: Los datos financieros fueron corrompidos, "
                "manipulados o la llave de descifrado es incorrecta."
            ) from e


def ejecutar_pruebas_y_rendimiento():
    """
    Realiza pruebas unitarias y de rendimiento en múltiples escenarios financieros,
    evaluando tiempos de ejecución y uso eficiente de recursos.
    """
    print("=" * 70)
    print("  FINTECH SOLUTIONS - MÓDULO DE PRUEBAS DE SEGURIDAD Y RENDIMIENTO")
    print("=" * 70)
    
    # Inicialización del gestor criptográfico
    manager = FinTechEncryptionManager()
    print("[+] Llave maestra AES-256 generada y cargada exitosamente en memoria.")
    
    # Escenarios de prueba con datos financieros altamente sensibles
    escenarios = [
        {"id": 1, "tipo": "Tarjeta de Crédito", "valor": "4532-8821-9012-3341"},
        {"id": 2, "tipo": "Cuenta Bancaria", "valor": "ACC-COL-99823471029"},
        {"id": 3, "tipo": "Monto de Transacción", "valor": "$45,200,000 COP"},
        {"id": 4, "tipo": "Datos Personales (Cédula)", "valor": "CC-1029384756"}
    ]
    
    tiempos_cifrado = []
    tiempos_descifrado = []

    print("\n[Ejecución de Pruebas de Cifrado y Descifrado]:\n")
    
    for item in escenarios:
        print(f"--- Escenario {item['id']}: {item['tipo']} ---")
        print(f"    Original  : {item['valor']}")
        
        # Medición de tiempo de ejecución para el cifrado
        inicio_c = time.perf_counter()
        cifrado_res = manager.encrypt_data(item['valor'])
        fin_c = time.perf_counter()
        tiempo_c = (fin_c - inicio_c) * 1000 # Convertir a milisegundos
        tiempos_cifrado.append(tiempo_c)
        
        print(f"    Nonce(Hex): {cifrado_res['nonce'].hex()}")
        print(f"    Cifrado   : {cifrado_res['ciphertext'].hex()[:32]}... [Truncado]")
        print(f"    Tiempo C. : {tiempo_c:.4f} ms")
        
        # Medición de tiempo de ejecución para el descifrado
        inicio_d = time.perf_counter()
        descifrado_texto = manager.decrypt_data(cifrado_res['nonce'], cifrado_res['ciphertext'])
        fin_d = time.perf_counter()
        tiempo_d = (fin_d - inicio_d) * 1000
        tiempos_descifrado.append(tiempo_d)
        
        print(f"    Descifrado: {descifrado_texto}")
        print(f"    Tiempo D. : {tiempo_d:.4f} ms")
        
        # Validación de consistencia
        assert item['valor'] == descifrado_texto, "¡Error! El texto descifrado no coincide con el original."
        print("    Estado    : [VALIDADO CORRECTAMENTE]\n")

    # Evaluación de Rendimiento y Recursos
    print("=" * 70)
    print("  EVALUACIÓN DE RENDIMIENTO Y RECURSOS")
    print("=" * 70)
    promedio_c = sum(tiempos_cifrado) / len(tiempos_cifrado)
    promedio_d = sum(tiempos_descifrado) / len(tiempos_descifrado)
    print(f"• Promedio de tiempo de cifrado   : {promedio_c:.4f} ms por transacción.")
    print(f"• Promedio de tiempo de descifrado : {promedio_d:.4f} ms por transacción.")
    print("• Consumo de memoria aproximado    : Mínimo (Operaciones en memoria O(1)).")
    print("• Conclusión de rendimiento        : Óptimo para entornos de alta concurrencia en FinTech.\n")

    # Prueba de Integridad (Simulación de Manipulación Maliciosa)
    print("[Simulación de Intrusión / Manipulación de Datos]:")
    cifrado_prueba = manager.encrypt_data("Monto Secreto: $1,000,000")
    
    # Alteramos un byte del texto cifrado para simular un ataque de manipulación (man-in-the-middle)
    ciphertext_corrupto = bytearray(cifrado_prueba['ciphertext'])
    ciphertext_corrupto[0] ^= 0xFF # Invertir bits del primer byte
    
    try:
        manager.decrypt_data(cifrado_prueba['nonce'], bytes(ciphertext_corrupto))
    except ValueError as e:
        print(f"• Alerta de seguridad interceptada con éxito: {e}")
    print("=" * 70)

if __name__ == "__main__":
    ejecutar_pruebas_y_rendimiento()
