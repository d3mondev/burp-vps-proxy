package vpsproxy.providers;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Scanner;
import javax.swing.JComponent;
import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import vpsproxy.Logger;
import vpsproxy.ProxySettings;

public abstract class Provider {
    private static final String proxyUsername = "burp-vps-proxy";
    private static final String proxyPort = "1080";

    private static final String SCRIPT_RESOURCE_PATH = "provisioning.sh";
    private static String SCRIPT;
    private static boolean debug = false;

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

    protected ProxySettings createProxySettings(String publicIpAddress, String password) {
        return new ProxySettings(publicIpAddress, proxyPort, proxyUsername, password);
    }

    public class ProviderException extends Exception {
        public ProviderException(String message, Throwable cause) {
            super(getName() + ": " + message, cause);
        }
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

    protected void runProvisioningScript(String ipAddress, String username, String password, String provisioningScript)
            throws Exception {
        log("provisioning via ssh");

        JSch jsch = new JSch();

        Session session = jsch.getSession(username, ipAddress, 22);
        session.setPassword(password);
        session.setConfig("StrictHostKeyChecking", "no");
        session.setConfig("ConnectTimeout", "60000");
        session.connect();

        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand("bash -s");
        channel.setInputStream(new ByteArrayInputStream(provisioningScript.getBytes(StandardCharsets.UTF_8)));
        channel.setErrStream(System.err);

        InputStream inputStream = channel.getInputStream();
        InputStream errorStream = channel.getErrStream();

        channel.connect();

        BufferedReader stdOutputReader = new BufferedReader(new InputStreamReader(inputStream));
        BufferedReader errOutputReader = new BufferedReader(new InputStreamReader(errorStream));

        String line;
        // log("Standard Output:");
        while ((line = stdOutputReader.readLine()) != null) {
            if (debug) {
                log(line);
            }
        }

        // log("Error Output:");
        while ((line = errOutputReader.readLine()) != null) {
            if (debug) {
                log(line);
            }
        }

        channel.disconnect();
        session.disconnect();
    }
}
