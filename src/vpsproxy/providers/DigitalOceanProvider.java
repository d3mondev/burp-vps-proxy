package vpsproxy.providers;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;

import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

public class DigitalOceanProvider implements Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String apiKeySetting = "ProviderDigitalOceanAPIKey";

    public DigitalOceanProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void startInstance() {
        // implementation for starting a DigitalOcean instance
    }

    @Override
    public void destroyInstance() {
        // implementation for destroying a DigitalOcean instance
    }

    @Override
    public String getName() {
        return "DigitalOcean";
    }

    @Override
    public ProxySettings getProxy() {
        // implementation for getting a DigitalOcean proxy
        return new ProxySettings("digitalocean.com", 8080, "user", "password", this);
    }

    @Override
    public JComponent getUI() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel apiKeyLabel = new JLabel("API key:");
        apiKeyLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextField apiKeyTextField = new JTextField();
        apiKeyTextField.setAlignmentX(Component.LEFT_ALIGNMENT);
        apiKeyTextField.setPreferredSize(new Dimension(200, apiKeyTextField.getPreferredSize().height));
        apiKeyTextField.setText(callbacks.loadExtensionSetting(apiKeySetting));

        panel.add(apiKeyLabel);
        panel.add(apiKeyTextField);

        apiKeyTextField.getDocument().addDocumentListener(new DocumentListener() {
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
                String value = apiKeyTextField.getText();
                callbacks.saveExtensionSetting(apiKeySetting, value);
            }
        });

        return panel;
    }
}
