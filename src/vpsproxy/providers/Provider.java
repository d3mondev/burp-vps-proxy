package vpsproxy.providers;

import java.io.InputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.swing.JComponent;
import vpsproxy.ProxySettings;

public abstract class Provider {
    private static final String SCRIPT_RESOURCE_PATH = "provisioning.sh";
    private static String SCRIPT;

    public abstract String getName();
    public abstract ProxySettings startInstance() throws IOException;
    public abstract void destroyInstance();
    public abstract JComponent getUI();

    protected String getProvisioningScript(String password) throws IOException {
        if (SCRIPT != null) {
            return SCRIPT;
        }

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(SCRIPT_RESOURCE_PATH);
        if (inputStream != null) {
            try (Scanner scanner = new Scanner(inputStream, "UTF-8")) {
                SCRIPT = scanner.useDelimiter("\\A").next();
            }
        } else {
            throw new IOException(String.format("Resource '%s' not found", SCRIPT_RESOURCE_PATH));
        }

        return SCRIPT.replaceAll("CHANGEME", password);
    }

    protected String getRandomString(int n) {
        String customAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz";

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[8];
        secureRandom.nextBytes(randomBytes);

        StringBuilder sb = new StringBuilder(6);
        for (int i = 0; i < n; i++) {
            int randomIndex = secureRandom.nextInt(customAlphabet.length());
            char randomChar = customAlphabet.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }
}
