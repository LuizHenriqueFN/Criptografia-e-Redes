package auxiliar;

import java.io.IOException;

public class ClearConsole {
    // Função que verifica qual o SO para limpar o console
    public static void clear() throws IOException, InterruptedException {
        //Limpa a tela no windows, no linux e no MacOS
        if (System.getProperty("os.name").contains("Windows"))
            new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
        else
            Runtime.getRuntime().exec("clear");

    }
}
