package vpsproxy.providers;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.event.*;
import com.myjeeva.digitalocean.DigitalOcean;
import com.myjeeva.digitalocean.common.DropletStatus;
import com.myjeeva.digitalocean.impl.DigitalOceanClient;
import com.myjeeva.digitalocean.pojo.Droplet;
import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

public class DigitalOceanProvider extends Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String apiKeySetting = "ProviderDigitalOceanAPIKey";

    public DigitalOceanProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public String getName() {
        return "DigitalOcean";
    }

    @Override
    public ProxySettings startInstance() throws IOException {
        log("creating a new droplet");

        DigitalOcean client = getClient();
        if (client == null) {
            return null;
        }

        String dropletName = String.format("burp-vps-proxy-%s", getRandomString(4));
        List<String> tags = new ArrayList<>();
        tags.add("burp-vps-proxy");

        Droplet droplet = new Droplet();
        droplet.setName(dropletName);
        droplet.setRegion(new com.myjeeva.digitalocean.pojo.Region("nyc"));
        droplet.setImage(new com.myjeeva.digitalocean.pojo.Image("debian-11-x64"));
        droplet.setSize("s-1vcpu-512mb-10gb");
        droplet.setTags(tags);

        String password = getRandomString(12);
        droplet.setUserData(getProvisioningScript(password));

        try {
            droplet = client.createDroplet(droplet);

            int attempts = 0;
            while (droplet.getStatus() != DropletStatus.ACTIVE) {
                Thread.sleep(2000);
                attempts++;

                if (attempts > 60) {
                    log("droplet creation timed out");
                    client.deleteDroplet(droplet.getId());
                    log("droplet deleted");
                    return null;
                }

                droplet = client.getDropletInfo(droplet.getId());
            }
        } catch (Exception e) {
            log(e.getMessage());
            return null;
        }

        logf("droplet %s created", droplet.getName());

        return new ProxySettings(droplet.getNetworks().getVersion4Networks().get(0).getIpAddress(), "1080", "burp-vps-proxy", password);
    }

    @Override
    public void destroyInstance() {
        DigitalOcean client = getClient();
        if (client == null) {
            return;
        }

        try {
            List<Droplet> droplets = client.getAvailableDroplets(0, Integer.MAX_VALUE).getDroplets();
            for (Droplet droplet : droplets) {
                List<String> tags = droplet.getTags();
                if (tags != null && tags.contains("burp-vps-proxy")) {
                    client.deleteDroplet(droplet.getId());
                    logf("droplet %s deleted", droplet.getName());
                }
            }
        } catch (Exception e) {
            log(e.getMessage());
            return;
        }
    }

    @Override
    public JComponent getUI() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel apiKeyLabel = new JLabel("API key:");
        apiKeyLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPasswordField apiKeyPasswordField = new JPasswordField();
        apiKeyPasswordField.setAlignmentX(Component.LEFT_ALIGNMENT);
        apiKeyPasswordField.setPreferredSize(new Dimension(200, apiKeyPasswordField.getPreferredSize().height));
        apiKeyPasswordField.setText(callbacks.loadExtensionSetting(apiKeySetting));

        panel.add(apiKeyLabel);
        panel.add(apiKeyPasswordField);

        apiKeyPasswordField.getDocument().addDocumentListener(new DocumentListener() {
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
                String value = new String(apiKeyPasswordField.getPassword());
                callbacks.saveExtensionSetting(apiKeySetting, value);
            }
        });

        return panel;
    }

    private DigitalOcean getClient() {
        String apiKey = callbacks.loadExtensionSetting(apiKeySetting);
        if (apiKey == null) {
            log("no API key defined");
            return null;
        }

        DigitalOcean client = new DigitalOceanClient(apiKey);
        try {
            client.getAccountInfo();
        } catch (Exception e) {
            log(e.getMessage());
            return null;
        }

        return client;
    }
}
