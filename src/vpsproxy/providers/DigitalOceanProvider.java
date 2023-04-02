package vpsproxy.providers;

import java.awt.*;
import java.awt.event.*;
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
    final private String DO_API_KEY_SETTING = "Provider_DigitalOcean_APIKey";
    final private String DO_REGION_SETTING = "Provider_DigitalOcean_Region";
    final private String[] DO_REGIONS = {
            "nyc1",
            "nyc3",
            "ams3",
            "sfo3",
            "sgp1",
            "lon1",
            "fra1",
            "tor1",
            "blr1",
            "syd1",
    };

    private IBurpExtenderCallbacks callbacks;
    private String doDropletTag = "burp-vps-proxy";
    private String doRegion = "nyc1";

    public DigitalOceanProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        String region = callbacks.loadExtensionSetting(DO_REGION_SETTING);
        if (region != null) {
            doRegion = region;
        }

        String burpInstanceId = callbacks.loadExtensionSetting(SettingsKeys.BURP_INSTANCE_ID);
        doDropletTag = doDropletTag + "-" + burpInstanceId;
    }

    @Override
    public String getName() {
        return "DigitalOcean";
    }

    @Override
    public ProxySettings startInstance() throws ProviderException {
        log("creating a new droplet");

        DigitalOcean client;
        try {
            client = getClient();

            String dropletName = String.format("burp-vps-proxy-%s", RandomString.generate(4));
            List<String> tags = new ArrayList<>();
            tags.add(doDropletTag);

            Droplet droplet = new Droplet();
            droplet.setName(dropletName);
            droplet.setRegion(new com.myjeeva.digitalocean.pojo.Region(doRegion));
            droplet.setImage(new com.myjeeva.digitalocean.pojo.Image("debian-11-x64"));
            droplet.setSize("s-1vcpu-512mb-10gb");
            droplet.setTags(tags);

            String password = RandomString.generate(12);
            droplet.setUserData(getProvisioningScript(password));

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

            logf("droplet %s created", droplet.getName());
            return new ProxySettings(droplet.getNetworks().getVersion4Networks().get(0).getIpAddress(), "1080",
                    "burp-vps-proxy", password);
        } catch (ProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new ProviderException(String.format("error creating droplet: %s", e.getMessage()), e);
        }
    }

    @Override
    public void destroyInstance() throws ProviderException {
        try {
            DigitalOcean client = getClient();

            List<Droplet> droplets = client.getAvailableDroplets(0, Integer.MAX_VALUE).getDroplets();
            for (Droplet droplet : droplets) {
                List<String> tags = droplet.getTags();
                if (tags != null && tags.contains(doDropletTag)) {
                    client.deleteDroplet(droplet.getId());
                    logf("droplet %s deleted", droplet.getName());
                }
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new ProviderException(String.format("error deleting droplet: %s", e.getMessage()), e);
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
        apiKeyPasswordField.setText(callbacks.loadExtensionSetting(DO_API_KEY_SETTING));

        JLabel doRegionLabel = new JLabel("Region:");
        doRegionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> doRegionComboBox = new JComboBox<>();
        doRegionComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        doRegionComboBox.setMaximumSize(new Dimension(75, doRegionComboBox.getPreferredSize().height));
        for (int i = 0; i < DO_REGIONS.length; i++) {
            doRegionComboBox.addItem(DO_REGIONS[i]);
        }

        String selectedRegion = callbacks.loadExtensionSetting(DO_REGION_SETTING);
        if (selectedRegion != null && !selectedRegion.isEmpty()) {
            doRegionComboBox.setSelectedItem(selectedRegion);
        }

        panel.add(apiKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(apiKeyPasswordField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(doRegionLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(doRegionComboBox);

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
                callbacks.saveExtensionSetting(DO_API_KEY_SETTING, value);
            }
        });

        doRegionComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Object selectedItem = doRegionComboBox.getSelectedItem();
                if (selectedItem == null) {
                    return;
                }

                doRegion = selectedItem.toString();
                callbacks.saveExtensionSetting(DO_REGION_SETTING, doRegion);
            }
        });

        return panel;
    }

    private DigitalOcean getClient() throws ProviderException {
        String apiKey = callbacks.loadExtensionSetting(DO_API_KEY_SETTING);
        if (apiKey == null) {
            throw new ProviderException("no api key defined", null);
        }

        DigitalOcean client = new DigitalOceanClient(apiKey);
        try {
            client.getAccountInfo();
        } catch (Exception e) {
            throw new ProviderException(String.format("error getting account info: %s", e.getMessage()), e);
        }

        return client;
    }
}
