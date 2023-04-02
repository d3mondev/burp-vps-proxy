package vpsproxy.providers;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.event.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import org.json.JSONArray;
import org.json.JSONObject;

import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

public class LinodeProvider extends Provider {
    public class InstanceInfo {
        private int id;
        private String label;

        public InstanceInfo(int id, String label) {
            this.id = id;
            this.label = label;
        }

        public int getId() {
            return id;
        }

        public String getLabel() {
            return label;
        }
    }

    final private String LINODE_API_BASE_URL = "https://api.linode.com/v4";
    final private String LINODE_API_CREATION_JSON = "{\"region\": \"%s\", \"type\": \"%s\", \"image\": \"%s\", \"root_pass\": \"%s\", \"label\": \"%s\", \"tags\": [\"%s\"]}";
    final private String LINODE_API_KEY_SETTING = "Provider_Linode_APIKey";
    final private String LINODE_REGION_SETTING = "Provider_Linode_Region";
    final private String LINODE_SIZE = "g6-nanode-1";
    final private String LINODE_IMAGE = "linode/debian11";
    final private int LINODE_TIMEOUT = 120;
    final private String[] LINODE_REGIONS = {
            "us-east",
            "us-central",
            "us-west",
            "us-southeast",
            "ca-central",
            "eu-west",
            "eu-central",
            "ap-south",
            "ap-northeast",
            "ap-west",
            "ap-southeast",
    };

    private IBurpExtenderCallbacks callbacks;
    private String linodeApiKey = "";
    private String linodeTag = "burp-vps-proxy";
    private String linodeRegion = "us-east";

    public LinodeProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        String burpInstanceId = callbacks.loadExtensionSetting(SettingsKeys.BURP_INSTANCE_ID);
        linodeTag = linodeTag + "-" + burpInstanceId;

        linodeApiKey = callbacks.loadExtensionSetting(LINODE_API_KEY_SETTING);
        String region = callbacks.loadExtensionSetting(LINODE_REGION_SETTING);
        if (region != null) {
            linodeRegion = region;
        }
    }

    @Override
    public String getName() {
        return "Linode";
    }

    @Override
    public ProxySettings startInstance() throws ProviderException {
        log("creating a new linode");

        try {
            String password = RandomString.generate(12);
            String rootPassword = RandomString.generate(24);
            String instanceName = String.format("burp-vps-proxy-%s", RandomString.generate(4));

            URL url = new URL(LINODE_API_BASE_URL + "/linode/instances");

            HttpURLConnection connection;
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + linodeApiKey);
            connection.setDoOutput(true);

            String payload = String.format(LINODE_API_CREATION_JSON, linodeRegion, LINODE_SIZE, LINODE_IMAGE,
                    rootPassword, instanceName, linodeTag);

            OutputStream os = connection.getOutputStream();
            os.write(payload.getBytes("UTF-8"));

            if (connection.getResponseCode() != 200) {
                throw new ProviderException("failed to created linode instance: "
                        + connection.getResponseCode() + " " + connection.getResponseMessage(), null);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));

            String output;
            StringBuilder sb = new StringBuilder();
            while ((output = br.readLine()) != null) {
                sb.append(output);
            }

            connection.disconnect();

            String responseJson = sb.toString();
            int instanceId = extractLinodeId(responseJson);
            String ipAddress = getInstanceIpAddress(instanceId);

            waitForStatus(instanceId, "running", LINODE_TIMEOUT);
            runProvisioningScript(ipAddress, "root", rootPassword, getProvisioningScript(password));

            logf("instance %s created", instanceName);
            return new ProxySettings(ipAddress, "1080", "burp-vps-proxy", password);
        } catch (ProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new ProviderException(String.format("error establishing connection: %s", e.getMessage()),
                    e);
        }
    }

    @Override
    public void destroyInstance() throws ProviderException {
        try {
            List<InstanceInfo> instanceInfos = getInstanceIdsWithTag(linodeTag);
            for (InstanceInfo instanceInfo : instanceInfos) {
                deleteLinodeInstance(instanceInfo.id);
                logf("instance %s deleted", instanceInfo.label);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new ProviderException(String.format("error deleting linode: %s", e.getMessage()),
                    e);
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
        apiKeyPasswordField.setText(linodeApiKey);

        JLabel linodeRegionLabel = new JLabel("Region:");
        linodeRegionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> linodeRegionComboBox = new JComboBox<>();
        linodeRegionComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        linodeRegionComboBox.setMaximumSize(new Dimension(125, linodeRegionComboBox.getPreferredSize().height));
        for (int i = 0; i < LINODE_REGIONS.length; i++) {
            linodeRegionComboBox.addItem(LINODE_REGIONS[i]);
        }

        String selectedRegion = callbacks.loadExtensionSetting(LINODE_REGION_SETTING);
        if (selectedRegion != null && !selectedRegion.isEmpty()) {
            linodeRegionComboBox.setSelectedItem(selectedRegion);
        }

        panel.add(apiKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(apiKeyPasswordField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(linodeRegionLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(linodeRegionComboBox);

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
                callbacks.saveExtensionSetting(LINODE_API_KEY_SETTING, value);
                linodeApiKey = value;
            }
        });

        linodeRegionComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Object selectedItem = linodeRegionComboBox.getSelectedItem();
                if (selectedItem == null) {
                    return;
                }

                linodeRegion = selectedItem.toString();
                callbacks.saveExtensionSetting(LINODE_REGION_SETTING, linodeRegion);
            }
        });

        return panel;
    }

    private void deleteLinodeInstance(int linodeId) throws Exception {
        URL url = new URL(LINODE_API_BASE_URL + "/linode/instances/" + linodeId);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("DELETE");
        connection.setRequestProperty("Authorization", "Bearer " + linodeApiKey);

        if (connection.getResponseCode() != 200) {
            throw new ProviderException("failed to delete instance: " + connection.getResponseCode() + " "
                    + connection.getResponseMessage(), null);

        }

        connection.disconnect();
    }

    private static int extractLinodeId(String json) {
        JSONObject responseJson = new JSONObject(json);
        return responseJson.getInt("id");
    }

    private String getInstanceDetails(int linodeId) throws Exception {
        URL url = new URL(LINODE_API_BASE_URL + "/linode/instances/" + linodeId);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + linodeApiKey);

        if (connection.getResponseCode() != 200) {
            throw new ProviderException("failed to get instance details: " + connection.getResponseCode() + " "
                    + connection.getResponseMessage(), null);
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String output;
        StringBuilder sb = new StringBuilder();
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }

        connection.disconnect();

        return sb.toString();
    }

    private String getInstanceIpAddress(int linodeId) throws Exception {
        String instanceDetails = getInstanceDetails(linodeId);
        JSONObject instanceJson = new JSONObject(instanceDetails);
        JSONArray ipv4Addresses = instanceJson.getJSONArray("ipv4");
        return ipv4Addresses.getString(0);
    }

    private String getInstanceStatus(int linodeId) throws Exception {
        String instanceDetails = getInstanceDetails(linodeId);
        JSONObject instanceJson = new JSONObject(instanceDetails);
        return instanceJson.getString("status");
    }

    private List<InstanceInfo> getInstanceIdsWithTag(String tag) throws Exception {
        URL url = new URL(LINODE_API_BASE_URL + "/linode/instances?tags=" + tag);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + linodeApiKey);

        if (connection.getResponseCode() != 200) {
            throw new ProviderException("failed to list instances: " + connection.getResponseCode() + " "
                    + connection.getResponseMessage(), null);
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String output;
        StringBuilder sb = new StringBuilder();
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }

        String responseJson = sb.toString();
        JSONObject jsonResponse = new JSONObject(responseJson);
        JSONArray instances = jsonResponse.getJSONArray("data");

        List<InstanceInfo> instanceInfos = new ArrayList<>();
        for (int i = 0; i < instances.length(); i++) {
            JSONObject instance = instances.getJSONObject(i);
            JSONArray instanceTags = instance.getJSONArray("tags");
            for (int j = 0; j < instanceTags.length(); j++) {
                if (tag.equals(instanceTags.getString(j))) {
                    instanceInfos.add(new InstanceInfo(instance.getInt("id"), instance.getString("label")));
                    break;
                }
            }
        }

        return instanceInfos;
    }

    private void waitForStatus(int linodeId, String status, int timeout) throws Exception {
        int elapsed = 0;

        while (true) {
            if (elapsed >= timeout) {
                throw new ProviderException(String.format("timed out waiting for status \"%s\"", status), null);
            }

            if (getInstanceStatus(linodeId).equalsIgnoreCase(status)) {
                break;
            }

            Thread.sleep(5000);
            elapsed += 5;
        }

        // Wait an extra 10 seconds otherwise the server may not be ready to accept
        // connections
        Thread.sleep(10000);
    }
}
