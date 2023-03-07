package vpsproxy;

import java.util.HashMap;
import java.util.Map;
import burp.IBurpExtenderCallbacks;
import vpsproxy.providers.DigitalOceanProvider;
import vpsproxy.providers.*;

public class VPSProxy {
    private OptionsTab optionsTab;

    private Map<String, Provider> providerMap;

    public VPSProxy(IBurpExtenderCallbacks callbacks) {
        Logger.log("starting");

        providerMap = new HashMap<String, Provider>();

        Provider awsProvider = new AWSProvider(callbacks);
        providerMap.put(awsProvider.getName(), awsProvider);

        Provider digitalOceanProvider = new DigitalOceanProvider(callbacks);
        providerMap.put(digitalOceanProvider.getName(), digitalOceanProvider);

        optionsTab = new OptionsTab(callbacks, providerMap);

        Logger.init(callbacks.getStdout(), optionsTab);

        Logger.log("hello");
    }

    public OptionsTab getUI() {
        return optionsTab;
    }

    public void close() {
        Logger.log("closing");

        Provider currentProvider = optionsTab.getSelectedProvider();
        if (currentProvider != null) {
            Logger.log("destroying instance");
            currentProvider.destroyInstance();
        }
    }
}
