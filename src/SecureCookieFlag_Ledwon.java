public class SecureCookieFlag_Ledwon implements VulnerabilityLogic {

    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        String sessionId = (userInput != null && !userInput.isEmpty()) ? userInput : "abc123";

        return "Set-Cookie: sessionId=" + sessionId;
    }
}
