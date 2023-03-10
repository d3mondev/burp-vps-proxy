package vpsproxy;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private static PrintWriter printWriter;
    private static VPSProxyTab optionsTab;

    public static void init(OutputStream stdout, VPSProxyTab tab) {
        printWriter = new PrintWriter(stdout, true);
        optionsTab = tab;
    }

    public static void log(String message) {
        log(message, true);
    }

    public static void log(String message, boolean timestamp) {
        if (timestamp) {
            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String ts = now.format(formatter);
            message = String.format("[%s] %s\n", ts, message);
        }

        if (printWriter != null) {
            printWriter.printf("%s", message);
        }

        if (optionsTab != null) {
            optionsTab.log(message);
        }
    }
}
