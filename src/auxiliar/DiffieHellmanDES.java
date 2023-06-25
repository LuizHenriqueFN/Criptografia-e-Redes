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
    No código apresentado abaaixo, é utilizado tanto criptografia simétrica quanto assimétrica.

    A criptografia simétrica é usada para criptografar e descriptografar as mensagens, e o algoritmo utilizado é o DES (Data Encryption Standard). A chave
    simétrica gerada pelo algoritmo de troca de chaves Diffie-Hellman é usada para inicializar o objeto Cipher e realizar a criptografia e descriptografia dos dados.

    Por outro lado, a criptografia assimétrica é utilizada no algoritmo de troca de chaves Diffie-Hellman. Esse algoritmo permite que duas partes
    (no caso do código fornecido, a classe DiffieHellmanDES) estabeleçam uma chave compartilhada sem realmente compartilhar a chave real. A chave pública
    é usada para trocar informações e calcular um valor comum (o segredo compartilhado), que é usado posteriormente para gerar a chave simétrica.

    Portanto, a criptografia simétrica (DES) é usada para criptografar e descriptografar as mensagens, enquanto a criptografia assimétrica (Diffie-Hellman) é usada para estabelecer a chave simétrica compartilhada.

    Essa combinação de criptografia simétrica e assimétrica é comumente usada em sistemas criptográficos híbridos, aproveitando a eficiência da criptografia simétrica e a segurança da criptografia assimétrica.
*/

public class DiffieHellmanDES {
	private KeyPairGenerator keyPairGenerator;
    private KeyAgreement keyAgreement;
    private KeyPair keyPair;
    private PublicKey publicKey;

    /*
        Declaração da classe DiffieHellmanDES, que é responsável por gerar chaves e realizar a troca de chaves de Diffie-Hellman, além de criptografar
        e descriptografar mensagens usando o algoritmo DES.

        No construtor da classe DiffieHellmanDES, temos a inicialização do gerador de chaves Diffie-Hellman através do método getInstance("DiffieHellman").
        Em seguida, o tamanho da chave é definido como 1024 bits através do método initialize(1024) do objeto keyPairGenerator. O par de chaves é gerado
        através do método generateKeyPair() e a chave pública é obtida através do método getPublic().
    */
    public DiffieHellmanDES() throws Exception {
        // Inicializa o gerador de chaves Diffie-Hellman
        keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
        keyPairGenerator.initialize(1024); // Tamanho da chave

        // Gera o par de chaves
        keyPair = keyPairGenerator.generateKeyPair();

        // Obtém a chave pública
        publicKey = keyPair.getPublic();
    }

    // Este método retorna a chave pública gerada pelo objeto keyPair.
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /*
        Este método gera o segredo compartilhado (chave simétrica) a partir da chave pública recebida como parâmetro. Ele inicializa o objeto keyAgreement
        com o algoritmo Diffie-Hellman através do método getInstance("DiffieHellman") e, em seguida, inicializa o acordo de chaves com a chave privada
        através do método init(keyPair.getPrivate()). O segredo compartilhado é gerado chamando keyAgreement.doPhase(receivedPublicKey, true) e
        keyAgreement.generateSecret(). Em seguida, é gerada uma chave simétrica a partir do segredo compartilhado utilizando a função hash SHA-1 e, 
        por fim, é retornada a chave simétrica (SecretKey).
    */
    public SecretKey generateSharedSecret(PublicKey receivedPublicKey) throws Exception {
        // Inicializa o acordo de chaves com a chave privada
        keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        keyAgreement.init(keyPair.getPrivate());

        // Gera o segredo compartilhado
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Gera uma chave simétrica a partir do segredo compartilhado
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] sharedSecretBytes = sha.digest(sharedSecret);
        byte[] keyBytes = new byte[8];
        System.arraycopy(sharedSecretBytes, 0, keyBytes, 0, 8);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DES");

        return secretKey;
    }

    /*
        Este método criptografa uma mensagem usando a chave simétrica recebida como parâmetro. Ele inicializa o objeto Cipher com o algoritmo DES, o modo
        de operação ECB (Electronic Codebook) e o preenchimento PKCS5Padding. Em seguida, a criptografia é realizada chamando cipher.doFinal(message.getBytes()),
        onde message é a mensagem a ser criptografada. Os bytes criptografados são convertidos para uma representação em Base64 e retornados como uma string.
    */
    public String encryptMessage(String message, SecretKey secretKey) throws Exception {
        // Criptografa a mensagem usando a chave simétrica
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        // Codifica os bytes criptografados para Base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /*
        Este método descriptografa uma mensagem criptografada usando a chave simétrica recebida como parâmetro. Ele decodifica a mensagem criptografada de
        Base64 para obter os bytes criptografados através de Base64.getDecoder().decode(encryptedMessage). Em seguida, o objeto Cipher é inicializado com o
        algoritmo DES, o modo de operação ECB e o preenchimento PKCS5Padding. A descriptografia é realizada chamando cipher.doFinal(encryptedBytes), onde
        encryptedBytes são os bytes criptografados. Os bytes descriptografados são convertidos para uma string e retornados.
    */
    public String decryptMessage(String encryptedMessage, SecretKey secretKey) throws Exception {
        // Decodifica a mensagem criptografada de Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);

        // Descriptografa a mensagem usando a chave simétrica
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}
