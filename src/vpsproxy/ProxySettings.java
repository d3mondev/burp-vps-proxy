package vpsproxy;

public class ProxySettings {
    private String ip;
    private String port;
    private String username;
    private String password;

    public ProxySettings(String ip, String port, String username, String password) {
        this.ip = ip;
        this.port = port;
        this.username = username;
        this.password = password;
    }

    public String getIp() {
        return ip;
    }

    public String getPort() {
        return port;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        String str = ip + ":" + port;

        if (username != null && !username.isEmpty()) {
            str += ":" + username;
        }

        if (password != null && !password.isEmpty()) {
            str += ":" + password;
        }

        return str;
    }
}
