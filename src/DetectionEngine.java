
import java.util.HashMap;

public class DetectionEngine {

    // Stores failed login attempts for each IP address
    private static HashMap<String, Integer> failedAttempts = new HashMap<>();

    public static String analyze(LogEntry log) {

        String eventType = log.getEventType().toLowerCase();
        String severity = log.getSeverity().toLowerCase();
        String ip = log.getIpAddress();

        // Rule 1: Count failed login attempts
        if (eventType.contains("failed login")) {

            // Get existing count, or start from zero
            int attempts = failedAttempts.getOrDefault(ip, 0);

            // Increase the count
            attempts++;

            // Save the updated count
            failedAttempts.put(ip, attempts);

            System.out.println("Failed login attempts from "
                    + ip + ": " + attempts);

            // Check for possible brute-force activity
            if (attempts >= 5) {
                return "SUSPICIOUS - Possible brute-force attack detected";
            }

            return "MONITORING - Failed login attempt ("
                    + attempts + "/5)";
        }

        // Rule 2: High-severity activity
        if (severity.equals("high")) {
            return "SUSPICIOUS - High severity activity";
        }

        // Rule 3: Unusual requests
        if (eventType.contains("unusual request")) {
            return "SUSPICIOUS - Unusual request detected";
        }

        // No rule matched
        return "NORMAL - No suspicious pattern detected";
    }
}
