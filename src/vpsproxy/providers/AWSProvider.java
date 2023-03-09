package vpsproxy.providers;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;

import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

public class AWSProvider extends Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String awsAccessKeySetting = "ProviderAWSAccessKey";
    final private String awsSecretKeySetting = "ProviderAWSSecretKey";

    public AWSProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public String getName() {
        return "AWS EC2";
    }

    @Override
    public ProxySettings startInstance() {
        // implementation for starting a DigitalOcean instance
        return null;
    }

    @Override
    public void destroyInstance() {
        // implementation for destroying a DigitalOcean instance
    }

    @Override
    public JComponent getUI() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel awsAccessKeyLabel = new JLabel("AWS Access Key:");
        awsAccessKeyLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextField awsAccessKeyTextField = new JTextField();
        awsAccessKeyTextField.setAlignmentX(Component.LEFT_ALIGNMENT);
        awsAccessKeyTextField.setPreferredSize(new Dimension(200, awsAccessKeyTextField.getPreferredSize().height));
        awsAccessKeyTextField.setText(callbacks.loadExtensionSetting(awsAccessKeySetting));

        JLabel awsSecretKeyLabel = new JLabel("AWS Secret Key:");
        awsSecretKeyLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextField awsSecretKeyTextField = new JTextField();
        awsSecretKeyTextField.setAlignmentX(Component.LEFT_ALIGNMENT);
        awsSecretKeyTextField.setPreferredSize(new Dimension(200, awsSecretKeyTextField.getPreferredSize().height));
        awsSecretKeyTextField.setText(callbacks.loadExtensionSetting(awsSecretKeySetting));

        panel.add(awsAccessKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsAccessKeyTextField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyTextField);

        awsAccessKeyTextField.getDocument().addDocumentListener(new DocumentListener() {
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
                String value = awsAccessKeyTextField.getText();
                callbacks.saveExtensionSetting(awsAccessKeySetting, value);
            }
        });

        awsSecretKeyTextField.getDocument().addDocumentListener(new DocumentListener() {
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
                String value = awsSecretKeyTextField.getText();
                callbacks.saveExtensionSetting(awsSecretKeySetting, value);
            }
        });

        return panel;
    }
}
