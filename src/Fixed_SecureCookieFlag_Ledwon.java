import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Fixed_SecureCookieFlag_Ledwon implements VulnerabilityLogic {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Pattern SAFE_INPUT_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,128}$");
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int RANDOM_BYTES = 32;

    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {

        // 1. WALIDACJA WEJŚCIA
        if (userInput == null || userInput.trim().isEmpty()) {
            throw new IllegalArgumentException("Session ID cannot be null or empty");
        }

        // 2. SANITYZACJA
        String sanitizedInput = sanitizeInput(userInput);

        // 3. WALIDACJA FORMATU
        if (!SAFE_INPUT_PATTERN.matcher(sanitizedInput).matches()) {
            throw new IllegalArgumentException("Invalid session ID format");
        }

        // 4. GENEROWANIE BEZPIECZNEGO SESSION ID
        String secureSessionId = generateSecureSessionId();

        // 5. DODANIE SYGNATURY HMAC dla integralności
        String signedSessionId = signSessionId(secureSessionId, context);

        // 6. BUDOWANIE CIASTECZKA Z WSZYSTKIMI FLAGAMI BEZPIECZEŃSTWA
        String cookieName = "sessionId";
        if (context != null && context.isProductionEnvironment()) {
            cookieName = "__Secure-" + cookieName;
        }

        StringBuilder cookieBuilder = new StringBuilder();
        cookieBuilder.append("Set-Cookie: ").append(cookieName).append("=").append(signedSessionId);

        // Flagi bezpieczeństwa
        cookieBuilder.append("; Secure");       // Tylko HTTPS
        cookieBuilder.append("; HttpOnly");     // Niedostępne dla JavaScript
        cookieBuilder.append("; SameSite=Strict"); // Ochrona przed CSRF

        // 7. CZAS ŻYCIA SESJI
        int maxAge = getSessionMaxAge(context);
        cookieBuilder.append("; Max-Age=").append(maxAge);

        // 8. OGRANICZENIE DOMENY I ŚCIEŻKI
        String domain = getSafeDomain(context);
        if (!domain.isEmpty()) {
            cookieBuilder.append("; Domain=").append(domain);
        }
        cookieBuilder.append("; Path=/");

        // 9. LOGOWANIE DLA AUDYTU (bez wrażliwych danych)
        logSessionCreation(sanitizedInput, context);

        return cookieBuilder.toString();
    }

    private String sanitizeInput(String input) {
        String cleaned = input.replaceAll("[^a-zA-Z0-9_-]", "");
        return cleaned.length() <= 128 ? cleaned : cleaned.substring(0, 128);
    }

    private String generateSecureSessionId() {
        byte[] randomBytes = new byte[RANDOM_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);

        String uuid = UUID.randomUUID().toString();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());

        String part1 = Base64.getUrlEncoder().withoutPadding().encodeToString((uuid + timestamp).getBytes());
        String part2 = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        return part1 + "." + part2;
    }

    private String signSessionId(String sessionId, EnvironmentContext context) throws Exception {
        String secret = getSecretKey(context);

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes("UTF-8"), HMAC_ALGORITHM);
        mac.init(secretKeySpec);

        byte[] signature = mac.doFinal(sessionId.getBytes("UTF-8"));
        String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);

        return sessionId + "." + encodedSignature;
    }

    private String getSecretKey(EnvironmentContext context) {
        if (context != null && context.getSecretKey() != null && !context.getSecretKey().isEmpty()) {
            return context.getSecretKey();
        }

        throw new IllegalStateException("Secret key not configured - provide via EnvironmentContext (Vault/HSM/ENV)");
    }

    private int getSessionMaxAge(EnvironmentContext context) {
        int defaultMaxAge = 1800;
        if (context != null && context.getSessionTimeout() > 0) {
            return Math.min(context.getSessionTimeout(), 7200);
        }
        return defaultMaxAge;
    }

    private String getSafeDomain(EnvironmentContext context) {
        if (context != null && context.getDomain() != null && !context.getDomain().isEmpty()) {
            String domain = context.getDomain().toLowerCase().trim();

            if (domain.matches("^[a-z0-9.-]+$")) {
                return domain;
            }
        }
        return "";
    }

    private void logSessionCreation(String originalInput, EnvironmentContext context) {
        String maskedInput = (originalInput != null && originalInput.length() > 4)
                ? originalInput.substring(0, 4) + "****"
                : "****";

        String ip = (context != null) ? context.getClientIp() : "unknown";

        System.out.println(String.format("[AUDIT] Session created at %s for input: %s, IP: %s",
                Instant.now().toString(), maskedInput, ip));
    }
}
