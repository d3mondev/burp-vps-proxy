package vpsproxy.providers;

import java.awt.*;
import javax.swing.*;
import vpsproxy.*;

public class DigitalOceanProvider implements Provider {
    @Override
    public void startInstance() {
        // implementation for starting a DigitalOcean instance
    }

    @Override
    public void destroyInstance() {
        // implementation for destroying a DigitalOcean instance
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

        panel.add(apiKeyLabel);
        panel.add(apiKeyTextField);

        return panel;
    }
}
