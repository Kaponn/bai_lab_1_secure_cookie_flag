public class EnvironmentContext {

    private final String secretKey;
    private final boolean production;
    private final int sessionTimeoutSeconds;
    private final String domain;
    private final String clientIp;

    public EnvironmentContext(String secretKey, boolean production, int sessionTimeoutSeconds, String domain, String clientIp) {
        this.secretKey = secretKey;
        this.production = production;
        this.sessionTimeoutSeconds = sessionTimeoutSeconds;
        this.domain = domain;
        this.clientIp = clientIp;
    }

    public EnvironmentContext() {
        this(null, false, 1800, "", "127.0.0.1");
    }

    public String getSecretKey() {
        return secretKey;
    }

    public boolean isProductionEnvironment() {
        return production;
    }

    public int getSessionTimeout() {
        return sessionTimeoutSeconds;
    }

    public String getDomain() {
        return domain;
    }

    public String getClientIp() {
        return clientIp;
    }

    @Override
    public String toString() {
        return "EnvironmentContext{" +
                "production=" + production +
                ", sessionTimeoutSeconds=" + sessionTimeoutSeconds +
                ", domain='" + domain + '\'' +
                ", clientIp='" + clientIp + '\'' +
                '}';
    }
}
