package vpsproxy.providers;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Optional;
import javax.swing.*;
import javax.swing.event.*;
import burp.IBurpExtenderCallbacks;
import vpsproxy.*;

import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.ec2.model.Image;

public class AWSProvider extends Provider {
    private IBurpExtenderCallbacks callbacks;

    final private String instanceTag = "burp-vps-proxy";
    final private String awsOsType = "debian-11";
    final private String awsInstanceArch = "arm64";
    final private InstanceType awsInstanceType = InstanceType.T4_G_NANO;

    final private String awsAccessKeySetting = "ProviderAWSAccessKey";
    final private String awsSecretKeySetting = "ProviderAWSSecretKey";
    final private String awsRegionSetting = "ProviderAWSRegion";
    final private String[] awsRegions = {
        "us-east-2",
        "us-east-1",
        "us-west-1",
        "us-west-2",
        "af-south-1",
        "ap-east-1",
        "ap-south-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-south-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-northeast-1",
        "ca-central-1",
        "eu-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-south-1",
        "eu-west-3",
        "eu-south-2",
        "eu-north-1",
        "eu-central-2",
        "me-south-1",
        "me-central-1",
        "sa-east-1",
    };

    private String awsRegion = "us-east-1";
    private Ec2Client ec2Client;

    public AWSProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public String getName() {
        return "AWS EC2";
    }

    @Override
    public ProxySettings startInstance() throws ProviderException {
        log("creating a new instance");

        Ec2Client ec2Client;
        try {
            ec2Client = createClient();
        } catch (ProviderException e) {
            throw e;
        }

        String password = getRandomString(12);
        String script;
        try {
            script = getProvisioningScript(password);
        } catch (IOException e) {
            throw new ProviderException(String.format("error loading provisioning script: %s", e.getMessage()), e);
        }

        String amiId;
        try {
            amiId = getAmiId(awsOsType, awsRegion);
        } catch (ProviderException e) {
            throw e;
        }

        String securityGroupId;
        try {
            securityGroupId = createSecurityGroup("burp-vps-proxy", "Allow traffic to port 1080 for the Burp SOCKS Proxy");
        } catch (ProviderException e) {
            throw e;
        }

        String instanceName = String.format("burp-vps-proxy-%s", getRandomString(4));
        Tag nameTag = Tag.builder()
            .key("Name")
            .value(instanceName)
            .build();

        Tag proxyTag = Tag.builder()
            .key(instanceTag)
            .value("")
            .build();

        TagSpecification tagSpecification = TagSpecification.builder()
            .resourceType("instance")
            .tags(nameTag, proxyTag)
            .build();

        RunInstancesRequest runRequest = RunInstancesRequest.builder()
            .instanceType(awsInstanceType)
            .maxCount(1)
            .minCount(1)
            .imageId(amiId)
            .userData(script)
            .tagSpecifications(tagSpecification)
            .securityGroupIds(securityGroupId)
            .build();

        RunInstancesResponse runResponse;
        String instanceId;
        try {
            runResponse = ec2Client.runInstances(runRequest);
            instanceId = runResponse.instances().get(0).instanceId();
            ec2Client.waiter().waitUntilInstanceRunning(r -> r.instanceIds(instanceId));
        } catch (Exception e) {
            throw new ProviderException(String.format("error creating instance: %s", e.getMessage()), e);
        }

        DescribeInstancesRequest describeRequest = DescribeInstancesRequest.builder()
            .instanceIds(instanceId)
            .build();

        DescribeInstancesResponse describeResponse;
        try {
            describeResponse = ec2Client.describeInstances(describeRequest);
        } catch (Exception e) {
            throw new ProviderException(String.format("error reading newly created instance: %s", e.getMessage()), e);
        }

        String publicIpAddress = describeResponse.reservations().get(0).instances().get(0).publicIpAddress();
        return createProxySettings(publicIpAddress, password);
    }

    @Override
    public void destroyInstance() throws ProviderException {
        Ec2Client ec2Client;
        try {
            ec2Client = createClient();
        } catch (ProviderException e) {
            throw e;
        }

        DescribeInstancesRequest describeRequest = DescribeInstancesRequest.builder()
            .filters(
                Filter.builder()
                    .name("tag-key")
                    .values(instanceTag)
                    .build(),
                Filter.builder()
                    .name("instance-state-name")
                    .values("pending", "running", "rebooting", "stopping", "stopped")
                    .build())
            .build();

        DescribeInstancesResponse describeResponse;
        try {
            describeResponse = ec2Client.describeInstances(describeRequest);
        } catch (Exception e) {
            throw new ProviderException(String.format("error listing instances: %s", e.getMessage()), e);
        }

        describeResponse.reservations().stream()
            .flatMap(reservation -> reservation.instances().stream())
            .forEach(instance -> {
                String instanceId = instance.instanceId();
                String instanceName = "";
                for (Tag tag : instance.tags()) {
                    if (tag.key().equals("Name")) {
                        instanceName = tag.value();
                        break;
                    }
                }

                TerminateInstancesRequest terminateRequest = TerminateInstancesRequest.builder()
                    .instanceIds(instanceId)
                    .build();

                try {
                    ec2Client.terminateInstances(terminateRequest);
                    logf("instance %s deleted", instanceName);
                } catch (Exception e) {
                    logf("error deleting instance '%s': %s", instanceName, e.getMessage());
                }
            });
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

        JPasswordField awsSecretKeyPasswordField = new JPasswordField();
        awsSecretKeyPasswordField.setAlignmentX(Component.LEFT_ALIGNMENT);
        awsSecretKeyPasswordField.setPreferredSize(new Dimension(200, awsSecretKeyPasswordField.getPreferredSize().height));
        awsSecretKeyPasswordField.setText(callbacks.loadExtensionSetting(awsSecretKeySetting));

        JLabel awsRegionLabel = new JLabel("Region:");
        awsRegionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> awsRegionComboBox = new JComboBox<>();
        awsRegionComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        awsRegionComboBox.setMaximumSize(new Dimension(125, awsRegionComboBox.getPreferredSize().height));
        for (int i = 0; i < awsRegions.length; i++) {
            awsRegionComboBox.addItem(awsRegions[i]);
        }

        String selectedRegion = callbacks.loadExtensionSetting(awsRegionSetting);
        if (selectedRegion != null && !selectedRegion.isEmpty()) {
            awsRegionComboBox.setSelectedItem(selectedRegion);
        }

        panel.add(awsAccessKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsAccessKeyTextField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyPasswordField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsRegionLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsRegionComboBox);

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

        awsSecretKeyPasswordField.getDocument().addDocumentListener(new DocumentListener() {
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
                String value = new String(awsSecretKeyPasswordField.getPassword());
                callbacks.saveExtensionSetting(awsSecretKeySetting, value);
            }
        });

        awsRegionComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Object selectedItem = awsRegionComboBox.getSelectedItem();
                if (selectedItem == null) {
                    return;
                }

                awsRegion = selectedItem.toString();
                callbacks.saveExtensionSetting(awsRegionSetting, awsRegion);
            }
        });

        return panel;
    }

    @Override
    protected String getProvisioningScript(String password) throws IOException {
        String script = super.getProvisioningScript(password);
        return Base64.getEncoder().encodeToString(script.getBytes());
    }

    private Ec2Client createClient() throws ProviderException {
        // Load the AWS keys from settings
        String awsAccessKey = callbacks.loadExtensionSetting(awsAccessKeySetting);
        String awsSecretKey = callbacks.loadExtensionSetting(awsSecretKeySetting);

        if (awsAccessKey == null || awsSecretKey == null || awsAccessKey.isEmpty() || awsSecretKey.isEmpty()) {
            throw new ProviderException("missing API key(s)", null);
        }

        try {
            // Configure the region
            Region region = Region.of(awsRegion);

            // Create the client
            AwsCredentials credentials = AwsBasicCredentials.create(awsAccessKey, awsSecretKey);
            ec2Client = Ec2Client.builder()
                .region(region)
                .credentialsProvider(() -> credentials)
                .build();
        } catch (Exception e) {
            throw new ProviderException(String.format("error creating AWS client: %s", e.getMessage()), e);
        }

        return ec2Client;
    }

    private String getAmiId(String osType, String region) throws ProviderException {
        // Filter by name
        Filter osFilter = Filter.builder()
            .name("name")
            .values(osType + "-*")
            .build();

        // Filter by architecture
        Filter architectureFilter = Filter.builder()
            .name("architecture")
            .values(awsInstanceArch)
            .build();

        // Find the requested image
        DescribeImagesRequest describeImagesRequest = DescribeImagesRequest.builder()
            .owners("136693071363") // Debian AMI owner ID
            .filters(osFilter, architectureFilter)
            .build();

        DescribeImagesResponse describeImagesResponse;
        try {
            describeImagesResponse = ec2Client.describeImages(describeImagesRequest);
        } catch (Exception e) {
            throw new ProviderException(String.format("failed to find image '%s': %s", osType, e.getMessage()), e);
        }

        Optional<Image> latestImage = describeImagesResponse.images().stream()
            .max(Comparator.comparing(Image::creationDate));

        // Return the most recent image found
        return latestImage.map(Image::imageId).orElse(null);
    }

    private String createSecurityGroup(String groupName, String groupDescription) throws ProviderException {
        // Check if the security group already exists
        DescribeSecurityGroupsResponse describeResponse;
        try {
            describeResponse = ec2Client.describeSecurityGroups();
        } catch (Exception e) {
            throw new ProviderException(String.format("error listing security groups: %s", e.getMessage()), e);
        }

        Optional<SecurityGroup> securityGroup = describeResponse.securityGroups().stream()
            .filter(sg -> sg.groupName().equals(groupName))
            .findFirst();

        if (securityGroup.isPresent()) {
            // Security group already exists, return its ID
            return securityGroup.get().groupId();
        }

        // Create the security group
        CreateSecurityGroupRequest createRequest = CreateSecurityGroupRequest.builder()
            .groupName(groupName)
            .description(groupDescription)
            .build();

        CreateSecurityGroupResponse createResponse;
        try {
            createResponse = ec2Client.createSecurityGroup(createRequest);
        } catch (Exception e) {
            throw new ProviderException(String.format("error creating security groups: %s", e.getMessage()), e);
        }

        String groupId = createResponse.groupId();

        // Add a rule to the security group that allows traffic to port 1080
        IpRange ipRange = IpRange.builder()
            .cidrIp("0.0.0.0/0")
            .build();
        IpPermission ipPermission = IpPermission.builder()
            .ipProtocol("tcp")
            .fromPort(1080)
            .toPort(1080)
            .ipRanges(ipRange)
            .build();
        AuthorizeSecurityGroupIngressRequest authorizeRequest = AuthorizeSecurityGroupIngressRequest.builder()
            .groupId(groupId)
            .ipPermissions(Collections.singletonList(ipPermission))
            .build();

        try {
            ec2Client.authorizeSecurityGroupIngress(authorizeRequest);
        } catch (Exception e) {
            throw new ProviderException(String.format("error authorizing security group ingress: %s", e.getMessage()), e);
        }

        // Return the ID of the security group
        return groupId;
    }

    public class CreateSecurityGroupException extends Exception {
        public CreateSecurityGroupException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
