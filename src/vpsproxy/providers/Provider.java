package vpsproxy.providers;

import javax.swing.JComponent;
import vpsproxy.ProxySettings;

public interface Provider {
    void startInstance();
    void destroyInstance();
    String getName();
    JComponent getUI();
    ProxySettings getProxy();
}
