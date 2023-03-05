package burp;

import javax.swing.*;

import java.awt.*;
import java.awt.event.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class VPSProxyTab implements ITab {
    private IBurpExtenderCallbacks callbacks;

    private JPanel panel;
    private JTextArea logTextArea;
    private JScrollPane logScrollPane;

    private Font defaultFont;
    private Font headerFont;
    private Color headerColor;
    private int gapSize = 25;

    public VPSProxyTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // Initialize fonts and colors
        JLabel defaultLabel = new JLabel();
        callbacks.customizeUiComponent(defaultLabel);

        defaultFont = defaultLabel.getFont();
        headerFont = defaultFont.deriveFont(Font.BOLD, defaultFont.getSize() + 2);

        Color defaultColor = defaultLabel.getForeground();
        if (defaultColor.getRed() > 128 && defaultColor.getGreen() > 128
                && defaultColor.getBlue() > 128)
            headerColor = Color.WHITE;
        else
            headerColor = Color.BLACK;

        // Initialize main panel
        this.panel = new JPanel();

        // Provider UI elements
        JLabel providerHeaderLabel = new JLabel("Provider");
        providerHeaderLabel.setFont(headerFont);
        providerHeaderLabel.setForeground(headerColor);

        JLabel providerHelp1Label = new JLabel(
                "Select the VPS provider you want to use and enter the proper API key(s). Then, you can click Deploy to launch a new proxy.");
        JLabel providerHelp2Label = new JLabel(
                "Once created, the extension will automatically configure your SOCKS5 proxy in Burp -> Settings -> Network -> Connections.");
        JLabel providerHelp3Label = new JLabel(
                "The proxy server will automatically be terminated when Burp exits or the extension is unloaded.");

        JComboBox<String> providerComboBox =
                new JComboBox<>(new String[] {"DigitalOcean", "Linode", "AWS"});
        providerComboBox
                .setMaximumSize(new Dimension(150, providerComboBox.getPreferredSize().height));

        JButton deployButton = new JButton("Deploy");
        JButton stopButton = new JButton("Stop");

        // Log UI elements
        JLabel logHeaderLabel = new JLabel("Log");
        logHeaderLabel.setFont(headerFont);
        logHeaderLabel.setForeground(headerColor);

        logTextArea = new JTextArea();
        logTextArea.setEditable(false);

        logScrollPane = new JScrollPane(logTextArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        JScrollBar verticalBar = logScrollPane.getVerticalScrollBar();
        verticalBar.setValue(verticalBar.getMaximum());

        // Layout
        GroupLayout layout = new GroupLayout(this.panel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(layout.createParallelGroup().addComponent(providerHeaderLabel)
                .addComponent(providerHelp1Label).addComponent(providerHelp2Label)
                .addComponent(providerHelp3Label)
                .addGroup(layout.createSequentialGroup().addComponent(providerComboBox)
                        .addComponent(deployButton).addComponent(stopButton))
                .addComponent(logHeaderLabel).addComponent(logScrollPane));

        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(providerHeaderLabel)
                .addComponent(providerHelp1Label).addComponent(providerHelp2Label)
                .addComponent(providerHelp3Label)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE,
                        gapSize)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(providerComboBox).addComponent(deployButton)
                        .addComponent(stopButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE,
                        2 * gapSize)
                .addComponent(logHeaderLabel).addComponent(logScrollPane));

        layout.linkSize(deployButton, stopButton);

        this.panel.setLayout(layout);
    }

    @Override
    public String getTabCaption() {
        return "VPS Proxy";
    }

    @Override
    public Component getUiComponent() {
        return this.panel;
    }

    public void log(String text) {
        JScrollBar verticalBar = logScrollPane.getVerticalScrollBar();
        boolean autoScroll = verticalBar.getValue() == verticalBar.getMaximum();

        if (autoScroll) {
            AdjustmentListener scroller = new AdjustmentListener() {
                @Override
                public void adjustmentValueChanged(AdjustmentEvent e) {
                    Adjustable adjustable = e.getAdjustable();
                    adjustable.setValue(verticalBar.getMaximum());
                    // We have to remove the listener, otherwise the
                    // user would be unable to scroll afterwards
                    verticalBar.removeAdjustmentListener(this);
                }
            };
            verticalBar.addAdjustmentListener(scroller);
        }

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String timestamp = now.format(formatter);

        logTextArea.append(String.format("[%s] %s\n", timestamp, text));
    }
}
