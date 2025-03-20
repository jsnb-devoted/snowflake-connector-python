import base64
from typing import Optional, Union, Tuple
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import paramiko
import os

class TokenEncryption:
    def __init__(self, key_name: Optional[str] = None) -> None:
        """
        Initialize the encryption class using a key from the SSH agent.
        
        Args:
            key_name (Optional[str]): Name or identifier of the key to use.
                                     If None, the first available key will be used.
        """
        self.key_name: Optional[str] = key_name
        self._key: Optional[bytes] = None
        self._init_vector_size: int = 16  # AES block size
        
    def _get_ssh_key(self) -> bytes:
        """
        Fetch a key from the SSH agent and derive an encryption key from it.
        
        Returns:
            bytes: The derived encryption key
            
        Raises:
            ValueError: If no keys are found or the specified key isn't found
            RuntimeError: If there's a problem connecting to the SSH agent
        """
        if self._key is not None:
            return self._key
            
        try:
            # Connect to the SSH agent
            agent = paramiko.Agent()
            
            # Get available keys
            keys: Tuple[paramiko.AgentKey, ...] = agent.get_keys()
            if not keys:
                raise ValueError("No keys found in SSH agent")
            
            # Select the appropriate key
            selected_key: paramiko.AgentKey
            if self.key_name:
                for key in keys:
                    # Try to match key comment or fingerprint
                    if self.key_name in str(key):
                        selected_key = key
                        break
                else:
                    raise ValueError(f"Key '{self.key_name}' not found in SSH agent")
            else:
                # Use the first key
                selected_key = keys[0]
            
            # Create a digest from the key's blob to use as an encryption key
            key_data: bytes = selected_key.asbytes()
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(key_data)
            self._key = digest.finalize()
            
            return self._key
            
        except Exception as e:
            raise RuntimeError(f"Failed to get key from SSH agent: {str(e)}")
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data using a key from the SSH agent.
        
        Args:
            data (Union[str, bytes]): The data to encrypt
            
        Returns:
            str: Base64-encoded encrypted data
        """
        print("-------------------- Encrypting data...")
        if isinstance(data, str):
            data_bytes: bytes = data.encode('utf-8')
        else:
            data_bytes = data
            
        # Get the key
        key: bytes = self._get_ssh_key()
        
        # Generate a random initialization vector
        iv: bytes = os.urandom(self._init_vector_size)
        
        # Apply padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data: bytes = padder.update(data_bytes) + padder.finalize()
        
        # Encrypt the data
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data: bytes = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data, then encode to base64
        result: bytes = base64.b64encode(iv + encrypted_data)
        return result.decode('utf-8')
    
    def decrypt(self, encrypted_data: Union[str, bytes]) -> str:
        """
        Decrypt data using a key from the SSH agent.
        
        Args:
            encrypted_data (Union[str, bytes]): Base64-encoded encrypted data
            
        Returns:
            str: Decrypted data as a UTF-8 string
        """
        print("-------------------- Decrypting data...")
        # Decode from base64
        if isinstance(encrypted_data, str):
            decoded_data: bytes = base64.b64decode(encrypted_data)
        else:
            decoded_data = encrypted_data
            
        # Get the key
        key: bytes = self._get_ssh_key()
        
        # Extract the IV and ciphertext
        iv: bytes = decoded_data[:self._init_vector_size]
        ciphertext: bytes = decoded_data[self._init_vector_size:]
        
        # Decrypt the data
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data: bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data: bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        # Return as a string
        return data.decode('utf-8')
