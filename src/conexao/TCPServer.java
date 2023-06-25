package conexao;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
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
    O código a seguir é a implementação de um servidor TCP em Java. Ele permite a comunicação com clientes por meio de sockets TCP/IP.

    O código realiza as seguintes etapas:

    1- Inicialização e configuração do servidor:
        - Solicita ao usuário a porta do servidor.
        - Cria um socket do servidor na porta fornecida.
    
    2- Loop principal do servidor:
        - Exibe um menu para o usuário com opções: ativar o servidor, trocar a porta ou encerrar o servidor.
        - Executa a ação correspondente à opção selecionada.
    
    3- Lógica de comunicação com o cliente:
        - Aguarda a conexão de um cliente.
        - Cria objetos de leitura e escrita para a comunicação com o cliente.
        - Solicita ao cliente uma porta de entrada.
        - Envia uma mensagem de configuração ao cliente contendo a porta de entrada.
        - Realiza a troca de chaves Diffie-Hellman com o cliente.
        - Recebe uma mensagem criptografada do cliente, descriptografa-a e exibe a mensagem descriptografada.
        - Verifica se a chave compartilhada é igual à chave compartilhada gerada a partir da chave pública do cliente.
        - Envia uma mensagem de sucesso ou de chave diferente ao cliente.
        - Fecha a conexão com o cliente.
        - O servidor continua executando em um loop principal até que o usuário escolha encerrar o servidor.

    Esse código demonstra um exemplo básico de servidor TCP que utiliza troca de chaves Diffie-Hellman para estabelecer um segredo compartilhado
    e criptografar a comunicação com o cliente. 
*/
public class TCPServer {
    public static void main(String[] args) {
        try {
            ClearConsole.clear();
            Scanner input = new Scanner(System.in);
            System.out.print("Porta do servidor: ");
            int serverPort = input.nextInt();
            
            // Cria o socket do servidor
            ServerSocket serverSocket = new ServerSocket(serverPort);
            
            do{
                System.out.print(
                    "\n1- Ativar servidor" +
                    "\n2- Trocar porta" +
                    "\n3- Encerrar servidor" +
                    "\n> "
                );
                int option = input.nextInt();
                ClearConsole.clear();
                
                switch(option){
                    case 1:
                        break;
                    case 2:
                        System.out.print("Porta do servidor: ");
                        serverPort = input.nextInt();
                        
                        // Cria o socket do servidor
                        serverSocket = new ServerSocket(serverPort);
                        break;
                    case 3:
                        serverSocket.close();
                        input.close();
                        return;
                    default:
                        System.out.println("ERRO! Opção inserida não existe. Tente novamente:");
                        continue;
                }

                System.out.println("\nServidor aguardando conexão na porta " + serverPort + "...\n\n");

                // Aguarda a conexão do cliente
                Socket clientSocket = serverSocket.accept();
                System.out.println("Cliente conectado: " + clientSocket.getInetAddress().getHostAddress());
    
                /*
                    Dois objetos são criados: BufferedReader chamado reader e PrintWriter chamado writer. Esses objetos são usados para ler e escrever
                    dados através da conexão com o cliente.

                    O BufferedReader é inicializado com um InputStreamReader que recebe a entrada do cliente por meio do método clientSocket.getInputStream().
                    O PrintWriter é inicializado com um OutputStreamWriter que envia a saída para o cliente por meio do método clientSocket.getOutputStream().
                */
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter writer = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()), true);
    
                // Solicita a porta de entrada ao cliente
                writer.println("Digite a porta de entrada: ");
                int entryPort = Integer.parseInt(reader.readLine());
                System.out.println("Porta de entrada recebida: " + entryPort);
    
                // Gera a mensagem de configuração do servidor
                String configMessage = "Porta de comunicação: " + entryPort;
                writer.println(configMessage);
                System.out.println("Mensagem de configuração enviada ao cliente: " + configMessage);
    
                /*
                    Um objeto DiffieHellmanDES é criado para realizar a troca de chaves Diffie-Hellman.
                    A chave pública é obtida chamando o método getPublicKey() no objeto diffieHellman.
                    A chave pública é convertida em uma string codificada em Base64 usando Base64.getEncoder().encodeToString(publicKey.getEncoded()).
                    A chave pública é enviada ao cliente usando writer.println(publicKeyString).
                    A chave pública é exibida no console.
                */
                DiffieHellmanDES diffieHellman = new DiffieHellmanDES();
                PublicKey publicKey = diffieHellman.getPublicKey();
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

                writer.println(publicKeyString);// Enviando Chave pública para o cliente
                System.out.println("Chave pública enviada ao cliente: ");
                System.out.println("\n \" " + publicKeyString + " \" \n");
    
                /*
                    O servidor lê a chave pública enviada pelo cliente usando reader.readLine().
                    A chave pública recebida é decodificada de Base64 para um array de bytes usando Base64.getDecoder().decode(receivedPublicKeyString).
                    Um objeto KeyFactory é criado, especificando o algoritmo "DiffieHellman", usando KeyFactory.getInstance("DiffieHellman").
                    A chave pública recebida é reconstruída a partir dos bytes decodificados usando keyFactory.generatePublic(new X509EncodedKeySpec(receivedPublicKeyBytes))
                    e armazenada na variável receivedPublicKey.
                */
                String receivedPublicKeyString = reader.readLine();
                byte[] receivedPublicKeyBytes = Base64.getDecoder().decode(receivedPublicKeyString);
                KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
                PublicKey receivedPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(receivedPublicKeyBytes));
    
                /*
                    O servidor gera o segredo compartilhado chamando o método generateSharedSecret(receivedPublicKey) no objeto diffieHellman.
                    Uma mensagem indicando que o segredo compartilhado foi gerado e exibida no console.
                */
                SecretKey sharedSecret = diffieHellman.generateSharedSecret(receivedPublicKey);
                System.out.println("Segredo compartilhado gerado.");
    
                // Recebe a mensagem do cliente
                String encryptedMessage = reader.readLine();
                System.out.println("Mensagem criptografada recebida: ");
                System.out.println("\n \" " + encryptedMessage + " \" \n");
    
                // Descriptografa a mensagem
                String decryptedMessage = diffieHellman.decryptMessage(encryptedMessage, sharedSecret);
                System.out.println("Mensagem descriptografada: " + decryptedMessage);
    
                /*
                    O servidor verifica se o segredo compartilhado é igual ao segredo compartilhado gerado a partir da chave pública recebida pelo cliente.
                    Se forem iguais, uma mensagem de sucesso é enviada ao cliente usando writer.println("Mensagem recebida com sucesso!") e uma mensagem de
                    sucesso é exibida no console.
                    Caso contrário, uma mensagem indicando que a chave é diferente é enviada ao cliente usando writer.println("Chave diferente. Mensagem não enviada.")
                    e uma mensagem correspondente é exibida no console.
                */
                if (sharedSecret.equals(diffieHellman.generateSharedSecret(receivedPublicKey))) {
                    // Envia a mensagem de sucesso ao cliente
                    writer.println("Mensagem recebida com sucesso!");
                    System.out.println("Mensagem de sucesso enviada ao cliente.");
                } else {
                    // Envia a mensagem de chave diferente ao cliente
                    writer.println("Chave diferente. Mensagem não enviada.");
                    System.out.println("Mensagem de chave diferente enviada ao cliente.");
                }
    
                // Fecha as conexão
                clientSocket.close();

            }while(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
