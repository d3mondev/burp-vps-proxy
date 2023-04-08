package vpsproxy.providers;

import java.awt.Dimension;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Properties;

import javax.swing.*;
import javax.swing.event.*;

import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.common.util.net.SshdSocketAddress;

public class SSHProvider extends Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String SSH_HOST = "Provider_SSH_Host";
    final private String SSH_PORT = "Provider_SSH_Port";
    final private String SSH_LOCALPORT = "Provider_SSH_LocalPort";
    final private String SSH_AUTH_USERNAME = "Provider_SSH_Username";
    final private String SSH_AUTH_PASSWORD = "Provider_SSH_Password";

    private SshTunnel tunnel;

    private static class SshTunnel {
        private final SshClient client;
        private final ClientSession session;
        private final SshdSocketAddress tun;

        public SshTunnel(SshClient client, ClientSession session, SshdSocketAddress tun) {
            this.client = client;
            this.session = session;
            this.tun = tun;
        }

        public void close() {
            if (session != null) {
                session.close(true);
            }
            if (client != null) {
                client.stop();
            }
        }

        public String getLocalHostname() {
            return tun.getHostName();
        }

        public int getLocalPort() {
            return tun.getPort();
        }
    }

    public SSHProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // org.apache.sshd tries to use BounceCastle by default but we can't seem
        // to do this in a Burp extension. Disable it so that the package uses the
        // default security providers
        Properties systemProperties = System.getProperties();
        systemProperties.put("org.apache.sshd.security.provider.BC.enabled", "false");
        System.setProperties(systemProperties);
    }

    @Override
    public String getName() {
        return "SSH (experimental)";
    }

    @Override
    public ProxySettings startInstance() throws ProviderException {
        // TODO: support automatic reconnecting when extension is loaded
        log("connecting to SSH proxy");

        String host = callbacks.loadExtensionSetting(SSH_HOST);
        String portStr = callbacks.loadExtensionSetting(SSH_PORT);
        String username = callbacks.loadExtensionSetting(SSH_AUTH_USERNAME);
        String password = callbacks.loadExtensionSetting(SSH_AUTH_PASSWORD);
        String localPortStr = callbacks.loadExtensionSetting(SSH_LOCALPORT);

        int port, localPort;
        try {
            port = Integer.parseInt(portStr);
            localPort = Integer.parseInt(localPortStr);
        } catch (Exception e) {
            throw new ProviderException("invalid port: " + e.getMessage(), e);
        }

        try {
            tunnel = createSshTunnel(host, port, username, password, localPort);
        } catch (Exception e) {
            if (tunnel != null) {
                tunnel.close();
            }
            throw new ProviderException("error creating SSH tunnel: " + e.getMessage(), e);
        }

        return new ProxySettings(tunnel.getLocalHostname(), Integer.toString(tunnel.getLocalPort()), "", "");
    }

    @Override
    public void destroyInstance() throws ProviderException {
        log("disconnecting SSH proxy");
        try {
            if (tunnel != null) {
                tunnel.close();
            }
        } catch (Exception e) {
            throw new ProviderException("error stopping ssh client: " + e.getMessage(), e);
        }
    }

    @Override
    public JComponent getUI() {
        final int textFieldWidth = 150;

        JPanel panel = new JPanel();

        // Info
        JLabel infoLabel = new JLabel("This provider enables the use of a remote SSH connection as a SOCKS5 proxy.");

        // Remote host
        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField();
        hostField.setMinimumSize(new Dimension(textFieldWidth, hostField.getPreferredSize().height));
        hostField.setMaximumSize(new Dimension(textFieldWidth, hostField.getPreferredSize().height));
        hostField.setText(callbacks.loadExtensionSetting(SSH_HOST));

        JLabel hostPortLabel = new JLabel("Port:");
        JTextField hostPortField = new JTextField();
        hostPortField.setMinimumSize(new Dimension(55, hostPortField.getPreferredSize().height));
        hostPortField.setMaximumSize(new Dimension(55, hostPortField.getPreferredSize().height));

        String hostPort = callbacks.loadExtensionSetting(SSH_PORT);
        hostPort = null;
        if (hostPort == null) {
            hostPort = "22";
            callbacks.saveExtensionSetting(SSH_PORT, hostPort);
        }
        hostPortField.setText(hostPort);

        // Credentials
        JLabel usernameLabel = new JLabel("Username:");
        JTextField usernameField = new JTextField();
        usernameField.setMinimumSize(new Dimension(textFieldWidth, usernameField.getPreferredSize().height));
        usernameField.setMaximumSize(new Dimension(textFieldWidth, usernameField.getPreferredSize().height));
        usernameField.setText(callbacks.loadExtensionSetting(SSH_AUTH_USERNAME));

        JLabel passwordLabel = new JLabel("Password:");
        JPasswordField passwordField = new JPasswordField();
        passwordField.setMinimumSize(new Dimension(textFieldWidth, passwordField.getPreferredSize().height));
        passwordField.setMaximumSize(new Dimension(textFieldWidth, passwordField.getPreferredSize().height));
        passwordField.setText(callbacks.loadExtensionSetting(SSH_AUTH_PASSWORD));

        // Local port for proxy
        JLabel localPortLabel = new JLabel("Local port:");
        JTextField localPortField = new JTextField();
        localPortField.setMinimumSize(new Dimension(55, localPortField.getPreferredSize().height));
        localPortField.setMaximumSize(new Dimension(55, localPortField.getPreferredSize().height));

        String localPort = callbacks.loadExtensionSetting(SSH_LOCALPORT);
        if (localPort == null) {
            localPort = "1080";
            callbacks.saveExtensionSetting(SSH_LOCALPORT, localPort);
        }
        localPortField.setText(localPort);

        GroupLayout layout = new GroupLayout(panel);
        layout.setAutoCreateGaps(true);

        panel.setLayout(layout);

        layout.setHorizontalGroup(layout.createParallelGroup()
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup()
                                .addComponent(hostLabel)
                                .addComponent(usernameLabel)
                                .addComponent(passwordLabel)
                                .addComponent(localPortLabel))
                        .addGroup(layout.createParallelGroup()
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(hostField)
                                        .addComponent(hostPortLabel)
                                        .addComponent(hostPortField))
                                .addComponent(usernameField)
                                .addComponent(passwordField)
                                .addComponent(localPortField))));

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGap(10)
                .addComponent(infoLabel)
                .addGroup(layout.createParallelGroup()
                        .addComponent(hostLabel)
                        .addComponent(hostField)
                        .addComponent(hostPortLabel)
                        .addComponent(hostPortField))
                .addGroup(layout.createParallelGroup()
                        .addComponent(usernameLabel)
                        .addComponent(usernameField))
                .addGroup(layout.createParallelGroup()
                        .addComponent(passwordLabel)
                        .addComponent(passwordField))
                .addGroup(layout.createParallelGroup()
                        .addComponent(localPortLabel)
                        .addComponent(localPortField)));

        hostField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveSetting();
            }

            private void saveSetting() {
                callbacks.saveExtensionSetting(SSH_HOST, hostField.getText());
            }
        });

        hostPortField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveSetting();
            }

            private void saveSetting() {
                callbacks.saveExtensionSetting(SSH_PORT, hostPortField.getText());
            }
        });

        usernameField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveSetting();
            }

            private void saveSetting() {
                callbacks.saveExtensionSetting(SSH_AUTH_USERNAME, usernameField.getText());
            }
        });

        passwordField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveSetting();
            }

            private void saveSetting() {
                String value = new String(passwordField.getPassword());
                callbacks.saveExtensionSetting(SSH_AUTH_PASSWORD, value);
            }
        });

        localPortField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveSetting();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveSetting();
            }

            private void saveSetting() {
                callbacks.saveExtensionSetting(SSH_LOCALPORT, localPortField.getText());
            }
        });

        return panel;
    }

    private static SshTunnel createSshTunnel(String host, int port, String username, String password, int localPort)
            throws IOException {
        final int timeout = 5000;
        SshClient client = SshClient.setUpDefaultClient();

        // Enable forwarding
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);

        // Accept all server keys
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);

        // Ignore default ~/.ssh/config
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);

        client.start();

        ClientSession session = client.connect(username, host, port)
                .verify(timeout)
                .getSession();

        session.addPasswordIdentity(password);

        AuthFuture authFuture = session.auth();
        boolean authCompleted = authFuture.await(timeout);
        if (!authCompleted || !session.isAuthenticated()) {
            throw new IOException("Authentication failed: Invalid username or password.");
        }

        // TODO: weird localhost
        InetAddress localhost = InetAddress.getLocalHost();
        SshdSocketAddress tunAddr = session
                .startDynamicPortForwarding(new SshdSocketAddress(localhost.getHostAddress(), localPort));

        return new SshTunnel(client, session, tunAddr);
    }
}
