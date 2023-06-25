package auxiliar;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
    No c�digo apresentado abaaixo, � utilizado tanto criptografia sim�trica quanto assim�trica.

    A criptografia sim�trica � usada para criptografar e descriptografar as mensagens, e o algoritmo utilizado � o DES (Data Encryption Standard). A chave
    sim�trica gerada pelo algoritmo de troca de chaves Diffie-Hellman � usada para inicializar o objeto Cipher e realizar a criptografia e descriptografia dos dados.

    Por outro lado, a criptografia assim�trica � utilizada no algoritmo de troca de chaves Diffie-Hellman. Esse algoritmo permite que duas partes
    (no caso do c�digo fornecido, a classe DiffieHellmanDES) estabele�am uma chave compartilhada sem realmente compartilhar a chave real. A chave p�blica
    � usada para trocar informa��es e calcular um valor comum (o segredo compartilhado), que � usado posteriormente para gerar a chave sim�trica.

    Portanto, a criptografia sim�trica (DES) � usada para criptografar e descriptografar as mensagens, enquanto a criptografia assim�trica (Diffie-Hellman) � usada para estabelecer a chave sim�trica compartilhada.

    Essa combina��o de criptografia sim�trica e assim�trica � comumente usada em sistemas criptogr�ficos h�bridos, aproveitando a efici�ncia da criptografia sim�trica e a seguran�a da criptografia assim�trica.
*/

public class DiffieHellmanDES {
	private KeyPairGenerator keyPairGenerator;
    private KeyAgreement keyAgreement;
    private KeyPair keyPair;
    private PublicKey publicKey;

    /*
        Declara��o da classe DiffieHellmanDES, que � respons�vel por gerar chaves e realizar a troca de chaves de Diffie-Hellman, al�m de criptografar
        e descriptografar mensagens usando o algoritmo DES.

        No construtor da classe DiffieHellmanDES, temos a inicializa��o do gerador de chaves Diffie-Hellman atrav�s do m�todo getInstance("DiffieHellman").
        Em seguida, o tamanho da chave � definido como 1024 bits atrav�s do m�todo initialize(1024) do objeto keyPairGenerator. O par de chaves � gerado
        atrav�s do m�todo generateKeyPair() e a chave p�blica � obtida atrav�s do m�todo getPublic().
    */
    public DiffieHellmanDES() throws Exception {
        // Inicializa o gerador de chaves Diffie-Hellman
        keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
        keyPairGenerator.initialize(1024); // Tamanho da chave

        // Gera o par de chaves
        keyPair = keyPairGenerator.generateKeyPair();

        // Obt�m a chave p�blica
        publicKey = keyPair.getPublic();
    }

    // Este m�todo retorna a chave p�blica gerada pelo objeto keyPair.
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /*
        Este m�todo gera o segredo compartilhado (chave sim�trica) a partir da chave p�blica recebida como par�metro. Ele inicializa o objeto keyAgreement
        com o algoritmo Diffie-Hellman atrav�s do m�todo getInstance("DiffieHellman") e, em seguida, inicializa o acordo de chaves com a chave privada
        atrav�s do m�todo init(keyPair.getPrivate()). O segredo compartilhado � gerado chamando keyAgreement.doPhase(receivedPublicKey, true) e
        keyAgreement.generateSecret(). Em seguida, � gerada uma chave sim�trica a partir do segredo compartilhado utilizando a fun��o hash SHA-1 e, 
        por fim, � retornada a chave sim�trica (SecretKey).
    */
    public SecretKey generateSharedSecret(PublicKey receivedPublicKey) throws Exception {
        // Inicializa o acordo de chaves com a chave privada
        keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        keyAgreement.init(keyPair.getPrivate());

        // Gera o segredo compartilhado
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Gera uma chave sim�trica a partir do segredo compartilhado
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] sharedSecretBytes = sha.digest(sharedSecret);
        byte[] keyBytes = new byte[8];
        System.arraycopy(sharedSecretBytes, 0, keyBytes, 0, 8);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DES");

        return secretKey;
    }

    /*
        Este m�todo criptografa uma mensagem usando a chave sim�trica recebida como par�metro. Ele inicializa o objeto Cipher com o algoritmo DES, o modo
        de opera��o ECB (Electronic Codebook) e o preenchimento PKCS5Padding. Em seguida, a criptografia � realizada chamando cipher.doFinal(message.getBytes()),
        onde message � a mensagem a ser criptografada. Os bytes criptografados s�o convertidos para uma representa��o em Base64 e retornados como uma string.
    */
    public String encryptMessage(String message, SecretKey secretKey) throws Exception {
        // Criptografa a mensagem usando a chave sim�trica
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        // Codifica os bytes criptografados para Base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /*
        Este m�todo descriptografa uma mensagem criptografada usando a chave sim�trica recebida como par�metro. Ele decodifica a mensagem criptografada de
        Base64 para obter os bytes criptografados atrav�s de Base64.getDecoder().decode(encryptedMessage). Em seguida, o objeto Cipher � inicializado com o
        algoritmo DES, o modo de opera��o ECB e o preenchimento PKCS5Padding. A descriptografia � realizada chamando cipher.doFinal(encryptedBytes), onde
        encryptedBytes s�o os bytes criptografados. Os bytes descriptografados s�o convertidos para uma string e retornados.
    */
    public String decryptMessage(String encryptedMessage, SecretKey secretKey) throws Exception {
        // Decodifica a mensagem criptografada de Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);

        // Descriptografa a mensagem usando a chave sim�trica
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}
