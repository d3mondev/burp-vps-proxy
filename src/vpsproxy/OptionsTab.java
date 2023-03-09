package vpsproxy;

import javax.swing.*;
import burp.ITab;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;
import vpsproxy.providers.Provider;

public class OptionsTab implements ITab {
    private Map<String, Provider> providerMap;
    VPSProxy extension;

    private JPanel panel;
    private JPanel providerPanel;
    private JTextArea logTextArea;
    private JScrollPane logScrollPane;
    private JComboBox<String> providerComboBox;
    private JButton deployButton;
    private JButton stopButton;

    private Font defaultFont;
    private Font headerFont;
    private Color headerColor;
    private int gapSize = 25;

    Thread workerThread;

    public OptionsTab(VPSProxy extension, Map<String, Provider> providers) {
        providerMap = providers;
        this.extension = extension;

        // Initialize fonts and colors
        JLabel defaultLabel = new JLabel();
        extension.getCallbacks().customizeUiComponent(defaultLabel);

        defaultFont = defaultLabel.getFont();
        headerFont = defaultFont.deriveFont(Font.BOLD, defaultFont.getSize() + 2);

        Color defaultColor = defaultLabel.getForeground();
        if (defaultColor.getRed() > 128 && defaultColor.getGreen() > 128 && defaultColor.getBlue() > 128)
            headerColor = Color.WHITE;
        else
            headerColor = Color.BLACK;

        // Initialize main panel
        this.panel = new JPanel();

        // Provider UI elements
        JLabel providerHeaderLabel = new JLabel("Provider");
        providerHeaderLabel.setFont(headerFont);
        providerHeaderLabel.setForeground(headerColor);

        JLabel providerHelp1Label = new JLabel("Select the VPS provider you want to use and enter the proper API key(s). Then, you can click Deploy to launch a new proxy.");
        JLabel providerHelp2Label = new JLabel("Once created, the extension will automatically configure your SOCKS5 proxy in Burp -> Settings -> Network -> Connections.");
        JLabel providerHelp3Label = new JLabel("The proxy server will automatically be terminated when Burp exits or the extension is unloaded.");

        providerComboBox = new JComboBox<>();
        providerComboBox.setMaximumSize(new Dimension(150, providerComboBox.getPreferredSize().height));
        for (String providerName : providerMap.keySet()) {
            providerComboBox.addItem(providerName);
        }

        String selectedProviderName = extension.getCallbacks().loadExtensionSetting("SelectedProvider");
        providerComboBox.setSelectedItem(selectedProviderName);

        deployButton = new JButton("Deploy");
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);

        // Provider settings UI elements
        FlowLayout providerLayout = new FlowLayout(FlowLayout.LEFT);
        providerLayout.setHgap(0);
        providerLayout.setVgap(0);

        providerPanel = new JPanel(providerLayout);
        providerPanel.setMaximumSize(new Dimension(Short.MAX_VALUE, 200));

        Provider currentProvider = getSelectedProvider();
        if (currentProvider != null) {
            providerPanel.add(currentProvider.getUI());
        }

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

        layout.setHorizontalGroup(layout.createParallelGroup()
            .addComponent(providerHeaderLabel)
            .addComponent(providerHelp1Label)
            .addComponent(providerHelp2Label)
            .addComponent(providerHelp3Label)
            .addGroup(layout.createSequentialGroup()
                .addComponent(providerComboBox)
                .addComponent(deployButton)
                .addComponent(stopButton))
            .addComponent(providerPanel)
            .addComponent(logHeaderLabel)
            .addComponent(logScrollPane));

        layout.setVerticalGroup(layout.createSequentialGroup()
            .addComponent(providerHeaderLabel)
            .addComponent(providerHelp1Label)
            .addComponent(providerHelp2Label)
            .addComponent(providerHelp3Label)
            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, gapSize)
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(providerComboBox)
                .addComponent(deployButton)
                .addComponent(stopButton))
            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, 5)
            .addComponent(providerPanel)
            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, 2 * gapSize)
            .addComponent(logHeaderLabel)
            .addComponent(logScrollPane));

        layout.linkSize(deployButton, stopButton);

        this.panel.setLayout(layout);

        installHandlers();
    }

    @Override
    public String getTabCaption() {
        return "VPS Proxy";
    }

    @Override
    public Component getUiComponent() {
        return this.panel;
    }

    public void log(String message) {
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

        logTextArea.append(message);
    }

    private void installHandlers() {
        // Event handlers
        providerComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Provider selectedProvider = getSelectedProvider();
                if (selectedProvider == null) {
                    return;
                }

                // Replace the provider UI panel with the new provider UI
                providerPanel.removeAll();
                providerPanel.add(selectedProvider.getUI());
                providerPanel.revalidate();
                providerPanel.repaint();

                extension.getCallbacks().saveExtensionSetting("SelectedProvider", selectedProvider.getName());
            }
        });

        deployButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Provider selectedProvider = getSelectedProvider();
                if (selectedProvider == null) {
                    Logger.log("No provider selected");
                    return;
                }

                if (workerThread != null && workerThread.isAlive()) {
                    Logger.log("Worker thread is already started!");
                    return;
                }

                setRunningState();

                workerThread = new Thread(() -> {
                    if (!extension.startInstance(selectedProvider)) {
                        setStoppedState();
                    }
                });
                workerThread.start();
            }
        });

        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Provider selectedProvider = getSelectedProvider();
                if (selectedProvider == null) {
                    Logger.log("No provider selected");
                    return;
                }

                if (workerThread != null && workerThread.isAlive()) {
                    Logger.log("Wait for instance to finish deploying...");
                    return;
                }

                setStoppedState();

                extension.destroyInstance(selectedProvider);
            }
        });
    }

    protected Provider getSelectedProvider() {
        Object selectedItem = providerComboBox.getSelectedItem();
        if (selectedItem == null) {
            return null;
        }

        String providerName = selectedItem.toString();
        Provider provider = providerMap.get(providerName);
        if (provider == null) {
            return null;
        }

        return provider;
    }

    private void setRunningState() {
        stopButton.setEnabled(true);
        stopButton.requestFocusInWindow();
        providerComboBox.setEnabled(false);
        deployButton.setEnabled(false);
    }

    private void setStoppedState() {
        deployButton.setEnabled(true);
        deployButton.requestFocusInWindow();
        providerComboBox.setEnabled(true);
        stopButton.setEnabled(false);
    }
}
