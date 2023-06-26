package conexao;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;

import auxiliar.DiffieHellmanDES;
import auxiliar.ClearConsole;

/*
    O código a seguir é um cliente TCP em Java que se conecta a um servidor remoto e realiza uma troca de chaves Diffie-Hellman para criptografar e enviar mensagens ao servidor.

    1- O programa solicita ao usuário o endereço do servidor, a porta do servidor e a mensagem a ser criptografada.
    2- Um loop permite que o usuário execute várias ações, como realizar a conexão, trocar o endereço do servidor, trocar a porta do servidor, alterar a mensagem ou cancelar a conexão.
    3- O programa cria um socket para se conectar ao servidor usando o endereço e a porta fornecidos pelo usuário.
    4- Objetos BufferedReader e PrintWriter são usados para ler e escrever dados no socket.
    5- O programa recebe solicitações e mensagens do servidor, realiza a troca de chaves Diffie-Hellman, gera o segredo compartilhado e criptografa a mensagem usando esse segredo.
    6- A mensagem criptografada é enviada ao servidor, e a resposta do servidor é exibida.
    7- O loop continua até que o usuário decida cancelar a conexão.
    8- O programa trata possíveis exceções e exibe mensagens de erro se ocorrerem.
*/
public class TCPClient {
    public static void main(String[] args) {
        try {
            ClearConsole.clear();
            Scanner input = new Scanner(System.in);

            System.out.print("Endereço do servidor: ");
            String serverAddress = input.nextLine();
            
            System.out.print("Porta do servidor: ");
            int serverPort = input.nextInt();
            input.nextLine();// Limpando buffer

            System.out.print("Insira a mensagem que será criptografada: ");
            String message = input.nextLine();

            do{
                System.out.print(
                    "\n1- Realizar conexão;" + 
                    "\n2- Trocar servidor;" + 
                    "\n3- Trocar porta servidor;" + 
                    "\n4- Alterar mensagem;" + 
                    "\n5- Cancelar conexão;" +
                    "\n> "
                );
                int option = input.nextInt();
                ClearConsole.clear();
            
                switch(option){
                    case 1:
                        break;
                    case 2:
                        input.nextLine();
                        System.out.print("Endereço do servidor: ");
                        serverAddress = input.nextLine();
                        continue;
                    case 3:
                        System.out.println("Porta do servidor: ");
                        serverPort = input.nextInt();
                        continue;
                    case 4:
                        input.nextLine();
                        System.out.print("Insira a mensagem que será criptografada: ");
                        message = input.nextLine();
                        continue;
                    case 5:
                        input.close();
                        return;
                    default:
                        System.out.println("ERRO! A opção inserida não existe. Tente novamente:");
                        continue;
                }

                // Cria o socket do cliente e se conecta ao servidor
                Socket socket = new Socket(serverAddress, serverPort);
                System.out.println("Conectado ao servidor " + serverAddress + ":" + serverPort);

                /*
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream())): Cria um objeto BufferedReader para ler dados
                    do servidor através do fluxo de entrada do socket.
                    PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true): Cria um objeto PrintWriter para escrever dados
                    para o servidor através do fluxo de saída do socket.
                */
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                // Recebe a solicitação da porta de entrada do servidor
                String portRequest = reader.readLine();
                System.out.print(portRequest);

                // Lê a porta de entrada digitada pelo usuário
                int entryPort = input.nextInt(); 
                input.nextLine();// Limpando buffer
                writer.println(entryPort);// Envia a porta para o Servidor

                // Recebe a mensagem de configuração do servidor
                String configMessage = reader.readLine();
                System.out.println("Mensagem de configuração recebida: " + configMessage);

                /*
                    String publicKeyString = reader.readLine(): Lê a chave pública do servidor recebida como uma string codificada.
                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString): Decodifica a string da chave pública em um array de bytes.
                    KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman"): Cria uma instância da classe KeyFactory para a geração da chave pública.
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)): Gera a chave pública do servidor a partir do array de bytes decodificado.
                */
                String publicKeyString = reader.readLine();
                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
                KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
                PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                System.out.println("Chave pública do servidor recebida.");

                /*
                    PublicKey clientPublicKey = diffieHellman.getPublicKey(): Obtém a chave pública do cliente gerada pelo objeto diffieHellman.
                    String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()): Codifica a chave pública do
                    cliente em uma string usando a codificação Base64.
                */
                DiffieHellmanDES diffieHellman = new DiffieHellmanDES();
                PublicKey clientPublicKey = diffieHellman.getPublicKey();
                String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());

                writer.println(clientPublicKeyString);// Enviando chave pública do cliente para o servidor
                System.out.println("Chave pública do cliente enviada ao servidor.");

                // SecretKey sharedSecret = diffieHellman.generateSharedSecret(publicKey): Gera o segredo compartilhado entre o cliente e o servidor usando a chave pública do servidor.
                SecretKey sharedSecret = diffieHellman.generateSharedSecret(publicKey);
                System.out.println("Segredo compartilhado gerado.");

                // Criptografa a mensagem usando o segredo compartilhado
                String encryptedMessage = diffieHellman.encryptMessage(message, sharedSecret);
                System.out.println("Mensagem criptografada: ");
                System.out.println("\n \" " + encryptedMessage + " \" \n");

                // Envia a mensagem criptografada ao servidor
                writer.println(encryptedMessage);
                System.out.println("Mensagem enviada ao servidor.");

                // Recebe a resposta do servidor
                String response = reader.readLine();
                System.out.println("Resposta do servidor: " + response);

                // Fecha a conexão
                socket.close();
            }while(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
