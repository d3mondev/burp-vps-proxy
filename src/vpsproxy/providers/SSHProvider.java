package vpsproxy.providers;

import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import java.util.Properties;

import javax.swing.*;
import javax.swing.event.*;

import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.common.util.net.SshdSocketAddress;

public class SSHProvider extends Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String SSH_HOST_KEY = "Provider_SSH_Host";
    final private String SSH_PORT_KEY = "Provider_SSH_Port";
    final private String SSH_LOCALPORT_KEY = "Provider_SSH_LocalPort";
    final private String SSH_AUTH_TYPE_KEY = "Provider_SSH_AuthType";
    final private String SSH_AUTH_USERNAME_KEY = "Provider_SSH_Username";
    final private String SSH_AUTH_PASSWORD_KEY = "Provider_SSH_Password";
    final private String SSH_AUTH_KEYFILE_KEY = "Provider_SSH_KeyFile";

    private SshTunnel tunnel;

    private JRadioButton passwordRadioButton;
    private JPasswordField passwordField;
    private JRadioButton keyFileRadioButton;
    private JTextField keyFilePathField;
    private JButton selectKeyFileButton;

    private static class SshTunnel {
        private final SshClient client;
        private final ClientSession session;

        public SshTunnel(SshClient client, ClientSession session) {
            this.client = client;
            this.session = session;
        }

        public void close() {
            if (session != null) {
                session.close(true);
            }
            if (client != null) {
                client.stop();
            }
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
        return "SSH";
    }

    @Override
    public ProxySettings startInstance() throws ProviderException {
        // TODO: support automatic reconnecting when extension is loaded
        log("connecting to SSH proxy");

        String host = callbacks.loadExtensionSetting(SSH_HOST_KEY);
        String portStr = callbacks.loadExtensionSetting(SSH_PORT_KEY);
        String username = callbacks.loadExtensionSetting(SSH_AUTH_USERNAME_KEY);
        String password = callbacks.loadExtensionSetting(SSH_AUTH_PASSWORD_KEY);
        String localPortStr = callbacks.loadExtensionSetting(SSH_LOCALPORT_KEY);

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

        // TODO: get real addr
        return new ProxySettings("127.0.0.1", localPortStr, "", "");
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
        JPanel panel = new JPanel();

        // Info
        JLabel infoLabel = new JLabel("This provider allows the use of a remote SSH connection as SOCKS5 proxy.");

        // Remote host
        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField();
        hostField.setPreferredSize(new Dimension(150, hostField.getPreferredSize().height));
        hostField.setText(callbacks.loadExtensionSetting(SSH_HOST_KEY));

        JLabel hostPortLabel = new JLabel("Port:");
        JTextField hostPortField = new JTextField();
        hostPortField.setPreferredSize(new Dimension(55, hostPortField.getPreferredSize().height));

        String hostPort = callbacks.loadExtensionSetting(SSH_PORT_KEY);
        hostPort = null;
        if (hostPort == null) {
            hostPort = "22";
            callbacks.saveExtensionSetting(SSH_PORT_KEY, hostPort);
        }
        hostPortField.setText(hostPort);

        // Credentials
        JLabel usernameLabel = new JLabel("Username:");
        JTextField usernameField = new JTextField();
        usernameField.setText(callbacks.loadExtensionSetting(SSH_AUTH_USERNAME_KEY));

        passwordRadioButton = new JRadioButton("Password:", true);
        passwordField = new JPasswordField();
        passwordField.setText(callbacks.loadExtensionSetting(SSH_AUTH_PASSWORD_KEY));

        keyFileRadioButton = new JRadioButton("Key File:", false);
        keyFilePathField = new JTextField();
        keyFilePathField.setText(callbacks.loadExtensionSetting(SSH_AUTH_KEYFILE_KEY));
        selectKeyFileButton = new JButton("Select file ...");

        ButtonGroup credsButtonGroup = new ButtonGroup();
        credsButtonGroup.add(passwordRadioButton);
        credsButtonGroup.add(keyFileRadioButton);

        String authType = callbacks.loadExtensionSetting(SSH_AUTH_TYPE_KEY);
        if (authType != null) {
            setAuthType(authType);
        } else {
            setAuthType("password");
        }

        // Local port for proxy
        JLabel localPortLabel = new JLabel("Local port:");
        JTextField localPortField = new JTextField();

        String localPort = callbacks.loadExtensionSetting(SSH_LOCALPORT_KEY);
        if (localPort == null) {
            localPort = "1080";
            callbacks.saveExtensionSetting(SSH_LOCALPORT_KEY, localPort);
        }
        localPortField.setText(localPort);

        GroupLayout layout = new GroupLayout(panel);
        layout.setAutoCreateGaps(true);
        layout.linkSize(hostField, usernameField, passwordField, keyFilePathField);
        layout.linkSize(hostPortField, localPortField);

        panel.setLayout(layout);

        layout.setHorizontalGroup(layout.createParallelGroup()
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup()
                                .addComponent(hostLabel)
                                .addComponent(usernameLabel)
                                .addComponent(passwordRadioButton)
                                .addComponent(keyFileRadioButton)
                                .addComponent(localPortLabel))
                        .addGroup(layout.createParallelGroup()
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(hostField)
                                        .addComponent(hostPortLabel)
                                        .addComponent(hostPortField))
                                .addComponent(usernameField)
                                .addComponent(passwordField)
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(keyFilePathField)
                                        .addComponent(selectKeyFileButton))
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
                        .addComponent(passwordRadioButton)
                        .addComponent(passwordField))
                .addGroup(layout.createParallelGroup()
                        .addComponent(keyFileRadioButton)
                        .addComponent(keyFilePathField)
                        .addComponent(selectKeyFileButton))
                .addGroup(layout.createParallelGroup()
                        .addComponent(localPortLabel)
                        .addComponent(localPortField)));

        passwordRadioButton.addActionListener(e -> {
            setAuthType("password");
        });

        keyFileRadioButton.addActionListener(e -> {
            setAuthType("keyfile");
        });

        selectKeyFileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(panel);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                keyFilePathField.setText(selectedFile.getAbsolutePath());
            }
        });

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
                callbacks.saveExtensionSetting(SSH_HOST_KEY, hostField.getText());
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
                callbacks.saveExtensionSetting(SSH_PORT_KEY, hostPortField.getText());
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
                callbacks.saveExtensionSetting(SSH_AUTH_USERNAME_KEY, usernameField.getText());
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
                callbacks.saveExtensionSetting(SSH_AUTH_PASSWORD_KEY, value);
            }
        });

        keyFilePathField.getDocument().addDocumentListener(new DocumentListener() {
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
                callbacks.saveExtensionSetting(SSH_AUTH_KEYFILE_KEY, keyFilePathField.getText());
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
                callbacks.saveExtensionSetting(SSH_LOCALPORT_KEY, localPortField.getText());
            }
        });

        return panel;
    }

    private static SshTunnel createSshTunnel(String host, int port, String username, String password, int localPort)
            throws IOException {
        SshClient client = SshClient.setUpDefaultClient();
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY); // Needed to ignore default ~/.ssh/config
        client.start();

        ClientSession session = client.connect(username, host, port)
                .verify()
                .getSession();

        // TODO: support key identity
        session.addPasswordIdentity(password);

        session.auth().verify();
        if (!session.isAuthenticated()) { // TODO: not working
            throw new IOException("Authentication failed: Invalid username or password.");
        }

        // TODO: get real localhost
        session.startDynamicPortForwarding(new SshdSocketAddress("127.0.0.1", localPort));

        return new SshTunnel(client, session);
    }

    private void setAuthType(String authType) {
        if (authType.equals("password")) {
            passwordRadioButton.setSelected(true);
            // passwordField.setEnabled(true);
            // keyFilePathField.setEnabled(false);
            // selectKeyFileButton.setEnabled(false);
            callbacks.saveExtensionSetting(SSH_AUTH_TYPE_KEY, "password");
        } else if (authType.equals("keyfile")) {
            keyFileRadioButton.setSelected(true);
            // passwordField.setEnabled(false);
            // keyFilePathField.setEnabled(true);
            // selectKeyFileButton.setEnabled(true);
            callbacks.saveExtensionSetting(SSH_AUTH_TYPE_KEY, "keyfile");
        }
    }
}
