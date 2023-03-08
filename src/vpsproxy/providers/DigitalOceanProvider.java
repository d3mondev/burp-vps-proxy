package vpsproxy.providers;

import java.awt.*;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import javax.swing.*;
import javax.swing.event.*;
import com.myjeeva.digitalocean.DigitalOcean;
import com.myjeeva.digitalocean.common.DropletStatus;
import com.myjeeva.digitalocean.impl.DigitalOceanClient;
import com.myjeeva.digitalocean.pojo.Droplet;
import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

public class DigitalOceanProvider implements Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String apiKeySetting = "ProviderDigitalOceanAPIKey";
    private String provisioningScript = "";

    public DigitalOceanProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        InputStream inputStream = DigitalOceanProvider.class.getClassLoader().getResourceAsStream("provisioning.sh");
        if (inputStream != null) {
            try (Scanner scanner = new Scanner(inputStream, "UTF-8")) {
                provisioningScript = scanner.useDelimiter("\\A").next();
            }
        } else {
            Logger.log("Resource 'provisioning.sh' not found");
        }
    }

    @Override
    public String getName() {
        return "DigitalOcean";
    }

    @Override
    public ProxySettings startInstance() {
        Logger.log("DigitalOcean: creating a new droplet");

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
        droplet.setUserData(provisioningScript.replace("CHANGEME", password));

        try {
            droplet = client.createDroplet(droplet);

            int attempts = 0;
            while (droplet.getStatus() != DropletStatus.ACTIVE) {
                Thread.sleep(2000);
                attempts++;

                if (attempts > 60) {
                    Logger.log(String.format("DigitalOcean: droplet creation timed out"));
                    client.deleteDroplet(droplet.getId());
                    Logger.log(String.format("DigitalOcean: droplet deleted"));
                    return null;
                }

                droplet = client.getDropletInfo(droplet.getId());
            }
        } catch (Exception e) {
            Logger.log(String.format("DigitalOcean: %s", e.getMessage()));
            return null;
        }

        Logger.log(String.format("DigitalOcean: droplet %s created", droplet.getName()));

        return new ProxySettings(droplet.getNetworks().getVersion4Networks().get(0).getIpAddress(), "1080", "burp-vps-proxy", password);
    }

    @Override
    public void destroyInstance() {
        Logger.log("DigitalOcean: destroying instance");

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
                    Logger.log(String.format("DigitalOcean: droplet %s deleted", droplet.getName()));
                }
            }
        } catch (Exception e) {
            Logger.log(String.format("DigitalOcean: %s", e.getMessage()));
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
            Logger.log(String.format("%s: no API key defined", getName()));
            return null;
        }

        DigitalOcean client = new DigitalOceanClient(apiKey);
        try {
            client.getAccountInfo();
        } catch (Exception e) {
            Logger.log(String.format("%s: %s", getName(), e.getMessage()));
            return null;
        }

        return client;
    }

    private String getRandomString(int n) {
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