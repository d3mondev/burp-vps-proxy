package vpsproxy;

import vpsproxy.providers.Provider;

public class ProxySettings {
    private Provider provider;
    private String ip;
    private int port;
    private String username;
    private String password;

    public ProxySettings(String ip, int port, String username, String password, Provider provider) {
        this.ip = ip;
        this.port = port;
        this.username = username;
        this.password = password;
        this.provider = provider;
    }

    public Provider getProvider() {
        return provider;
    }

    public String getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
