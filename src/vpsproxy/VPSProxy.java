package vpsproxy;

import java.util.HashMap;
import java.util.Map;
import burp.IBurpExtenderCallbacks;
import vpsproxy.providers.DigitalOceanProvider;
import vpsproxy.providers.*;

public class VPSProxy {
    private VPSProxyTab optionsTab;
    private Map<String, Provider> providerMap;

    public VPSProxy(IBurpExtenderCallbacks callbacks) {
        providerMap = new HashMap<String, Provider>();
        providerMap.put("AWS", new AWSProvider());
        providerMap.put("DigitalOcean", new DigitalOceanProvider());

        optionsTab = new VPSProxyTab(callbacks, providerMap);
    }

    public VPSProxyTab getUI() {
        return optionsTab;
    }
}
