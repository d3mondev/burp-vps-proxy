package vpsproxy.providers;

import javax.swing.JComponent;
import vpsproxy.ProxySettings;

public interface Provider {
    void startInstance();
    void destroyInstance();
    ProxySettings getProxy();
    JComponent getUI();
}
