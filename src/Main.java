public class Main {
    public static void main(String[] args) throws Exception {

        String demoSecret = "super-secret-key-from-vault-or-env";
        EnvironmentContext ctx = new EnvironmentContext(demoSecret, true, 1800, "example.com", "192.0.2.1");

        VulnerabilityLogic secure = new Fixed_SecureCookieFlag_Ledwon();

        String secureHeader = secure.process("abc123", ctx);

        System.out.println("=== SECURE COOKIE HEADER ===");
        System.out.println(secureHeader);

        SecureCookieFlag_Ledwon vulnerable = new SecureCookieFlag_Ledwon();

        String vulnerableHeader = vulnerable.process("TestUser123", ctx);

        System.out.println("=== VULNERABLE COOKIE HEADER ===");
        System.out.println(vulnerableHeader);

    }
}
