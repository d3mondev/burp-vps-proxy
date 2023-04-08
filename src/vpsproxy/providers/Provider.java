package vpsproxy.providers;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Base64;
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

/**
 * Implements the base Provider class from which all providers derive.
 */
public abstract class Provider {
    public class ProviderException extends Exception {
        public ProviderException(String message, Throwable cause) {
            super(getName() + ": " + message, cause);
        }
    }

    private static final String PROXY_USERNAME = "burp-vps-proxy";
    private static final String PROXY_PORT = "1080";
    private static final String SCRIPT_RESOURCE_PATH = "provisioning.sh";
    private static String script;
    private static boolean debug = false;

    /**
     * Gets the name of the provider
     *
     * @return the name of the provider
     */
    public abstract String getName();

    /**
     * Starts a new VPS instance on the provider.
     *
     * The instance should have a tag that allows the destroyInstance() method to
     * delete
     * all the instances created by the extension.
     *
     * Additionnally, the startInstance method should ensure that the VPS is
     * correctly configured as
     * a SOCKS5 proxy with a username and adequate password.
     *
     * @return The settings of the newly-created proxy
     * @throws ProviderException
     */
    public abstract ProxySettings startInstance() throws ProviderException;

    /**
     * Destroys all the instances started by the extension on the provider.
     *
     * All instances that have been tagged by the startInstance method should be
     * destroyed.
     * This ensures that instances failing to start correctly are also removed
     * from the provider, helping payment for orphaned instances.
     *
     * Extra caution is necessary to ensure ONLY tagged instances are deleted,
     * as deleting active VPS instances in the account may occur otherwise.
     *
     * @throws ProviderException
     */
    public abstract void destroyInstance() throws ProviderException;

    /**
     * Creates the UI containing the extension's settings.
     *
     * @return A JComponent containing the UI components, typically a JPanel
     */
    public abstract JComponent getUI();

    /**
     * Closes any resources used by the provider.
     *
     * Close is called whether the current provider is active or not.
     * Typically, this function doesn't need to do anything unless
     * there are special resources that need to be deleted when the extension
     * is unloaded.
     *
     * @throws ProviderException
     */
    public void close() throws ProviderException {
    }

    /**
     * Called on the current provider when the extension is loaded
     * and the provider is active. This method is called after the proxy
     * settings have been restored in Burp Suite.
     *
     * It should only be used if the provider needs to perform some sort of action
     * in order to activate the proxy. Typically, this function doesn't need
     * to do anything.
     *
     * @throws ProviderException
     */
    public void onRestore() throws ProviderException {
    }

    protected final void log(String message) {
        Logger.log(String.format("%s: %s", getName(), message));
    }

    protected final void logf(String format, Object... args) {
        format = getName() + ": " + format;
        Logger.log(String.format(format, args));
    }

    protected final ProxySettings createProxySettings(String publicIpAddress, String password) {
        return new ProxySettings(publicIpAddress, PROXY_PORT, PROXY_USERNAME, password);
    }

    protected final String getProvisioningScript(String password, boolean base64) throws IOException {
        if (script == null) {
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream(SCRIPT_RESOURCE_PATH);
            if (inputStream != null) {
                try (Scanner scanner = new Scanner(inputStream, "UTF-8")) {
                    script = scanner.useDelimiter("\\A").next();
                }
            } else {
                throw new IOException(String.format("Resource '%s' not found", SCRIPT_RESOURCE_PATH));
            }
        }

        String finalScript = script.replaceAll("CHANGEME", password);
        if (base64) {
            return Base64.getEncoder().encodeToString(finalScript.getBytes());
        } else {
            return finalScript;
        }
    }

    protected final void executeRemoteProvisioningScript(String ipAddress, String username, String password,
            String provisioningScript)
            throws Exception {
        log("provisioning via ssh");

        JSch jsch = new JSch();

        // TODO: Retry when failing to connect
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
        if (debug) {
            log("Standard Output:");
        }
        while ((line = stdOutputReader.readLine()) != null) {
            if (debug) {
                log(line);
            }
        }

        if (debug) {
            log("Error Output:");
        }
        while ((line = errOutputReader.readLine()) != null) {
            if (debug) {
                log(line);
            }
        }

        channel.disconnect();
        session.disconnect();
    }
}
