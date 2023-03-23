package vpsproxy.providers;

import java.io.InputStream;
import java.io.IOException;
import java.util.Scanner;
import javax.swing.JComponent;
import vpsproxy.Logger;
import vpsproxy.ProxySettings;

public abstract class Provider {
    private static final String proxyUsername = "burp-vps-proxy";
    private static final String proxyPort = "1080";

    private static final String SCRIPT_RESOURCE_PATH = "provisioning.sh";
    private static String SCRIPT;

    public abstract String getName();
    public abstract ProxySettings startInstance() throws ProviderException;
    public abstract void destroyInstance() throws ProviderException;
    public abstract JComponent getUI();

    protected void log(String message) {
        Logger.log(String.format("%s: %s", getName(), message));
    }

    protected void logf(String format, Object... args) {
        format = getName() + ": " + format;
        Logger.log(String.format(format, args));
    }

    protected String getProvisioningScript(String password) throws IOException {
        if (SCRIPT == null) {
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream(SCRIPT_RESOURCE_PATH);
            if (inputStream != null) {
                try (Scanner scanner = new Scanner(inputStream, "UTF-8")) {
                    SCRIPT = scanner.useDelimiter("\\A").next();
                }
            } else {
                throw new IOException(String.format("Resource '%s' not found", SCRIPT_RESOURCE_PATH));
            }
        }

        return SCRIPT.replaceAll("CHANGEME", password);
    }

    protected ProxySettings createProxySettings(String publicIpAddress, String password) {
        return new ProxySettings(publicIpAddress, proxyPort, proxyUsername, password);
    }

    public class ProviderException extends Exception {
        public ProviderException(String message, Throwable cause) {
            super(getName() + ": " + message, cause);
        }
    }
}
