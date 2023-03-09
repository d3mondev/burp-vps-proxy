package vpsproxy.providers;

import java.awt.*;
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

    final private String awsAccessKeySetting = "ProviderAWSAccessKey";
    final private String awsSecretKeySetting = "ProviderAWSSecretKey";
    final private String awsRegion = "us-east-1";

    private Ec2Client ec2Client;

    public AWSProvider(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public String getName() {
        return "AWS EC2";
    }

    @Override
    public ProxySettings startInstance() {
        log("creating a new instance");

        Ec2Client ec2Client = createClient();
        if (ec2Client == null) {
            return null;
        }

        String script;
        String password = getRandomString(12);
        try {
            script = getProvisioningScript(password);
        } catch (IOException e) {
            log(e.getMessage());
            return null;
        }

        String amiId = getAmiId("debian-11", awsRegion);
        if (amiId == null) {
            log("couldn't find image for 'debian-11'");
            return null;
        }

        String securityGroupId = createSecurityGroup("burp-vps-proxy", "Allow traffic to port 1080 for the Burp SOCKS Proxy");

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
                .instanceType(InstanceType.T2_MICRO)
                .maxCount(1)
                .minCount(1)
                .imageId(amiId)
                .userData(script)
                .tagSpecifications(tagSpecification)
                .securityGroupIds(securityGroupId)
                .build();

        RunInstancesResponse runResponse = ec2Client.runInstances(runRequest);
        String instanceId = runResponse.instances().get(0).instanceId();

        ec2Client.waiter().waitUntilInstanceRunning(r -> r.instanceIds(instanceId));

        DescribeInstancesRequest describeRequest = DescribeInstancesRequest.builder()
                .instanceIds(instanceId)
                .build();

        DescribeInstancesResponse describeResponse = ec2Client.describeInstances(describeRequest);
        String publicIpAddress = describeResponse.reservations().get(0).instances().get(0).publicIpAddress();

        return createProxySettings(publicIpAddress, password);
    }

    @Override
    public void destroyInstance() {
        Ec2Client ec2Client = createClient();
        if (ec2Client == null) {
            return;
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

        DescribeInstancesResponse describeResponse = ec2Client.describeInstances(describeRequest);

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

                    ec2Client.terminateInstances(terminateRequest);

                    logf("instance %s deleted", instanceName);
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

        panel.add(awsAccessKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsAccessKeyTextField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyLabel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(awsSecretKeyPasswordField);

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

        return panel;
    }

    @Override
    protected String getProvisioningScript(String password) throws IOException {
        String script = super.getProvisioningScript(password);
        return Base64.getEncoder().encodeToString(script.getBytes());
    }

    private Ec2Client createClient() {
        // Load the AWS keys from settings
        String awsAccessKey = callbacks.loadExtensionSetting(awsAccessKeySetting);
        String awsSecretKey = callbacks.loadExtensionSetting(awsSecretKeySetting);

        if (awsAccessKey == null || awsSecretKey == null) {
            log("missing API key(s)");
            return null;
        }

        // Configure the region
        Region region;
        try {
            region = Region.of(awsRegion);
        } catch (Exception e) {
            logf("%s: '%s' is not a valid region", getName(), awsRegion);
            return null;
        }

        // Create the client
        AwsCredentials credentials = AwsBasicCredentials.create(awsAccessKey, awsSecretKey);
        ec2Client = Ec2Client.builder()
                .region(region)
                .credentialsProvider(() -> credentials)
                .build();

        return ec2Client;
    }

    private String getAmiId(String osType, String region) {
        // Filter by name
        Filter osFilter = Filter.builder()
                .name("name")
                .values(osType + "-*")
                .build();

        // Filter by architecture
        Filter architectureFilter = Filter.builder()
                .name("architecture")
                .values("x86_64")
                .build();

        // Find the requested image
        DescribeImagesRequest describeImagesRequest = DescribeImagesRequest.builder()
                .owners("136693071363") // Debian AMI owner ID
                .filters(osFilter, architectureFilter)
                .build();

        DescribeImagesResponse describeImagesResponse = ec2Client.describeImages(describeImagesRequest);
        Optional<Image> latestImage = describeImagesResponse.images().stream()
                .max(Comparator.comparing(Image::creationDate));

        // Return the most recent image found
        return latestImage.map(Image::imageId).orElse(null);
    }

    private String createSecurityGroup(String groupName, String groupDescription) {
        // Check if the security group already exists
        DescribeSecurityGroupsResponse describeResponse = ec2Client.describeSecurityGroups();
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
        CreateSecurityGroupResponse createResponse = ec2Client.createSecurityGroup(createRequest);
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
        ec2Client.authorizeSecurityGroupIngress(authorizeRequest);

        // Return the ID of the security group
        return groupId;
    }
}
