
public class LogEntry {

    // Information about a security event
    private String ipAddress;
    private String eventType;
    private String description;
    private String severity;

    // Constructor: creates a new security log
    public LogEntry(String ipAddress, String eventType,
                    String description, String severity) {

        this.ipAddress = ipAddress;
        this.eventType = eventType;
        this.description = description;
        this.severity = severity;
    }

    // Getters: allow us to access the private data
    public String getIpAddress() {
        return ipAddress;
    }

    public String getEventType() {
        return eventType;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    // Display the security log
    public void displayLog() {
        System.out.println("IP Address: " + ipAddress);
        System.out.println("Event Type: " + eventType);
        System.out.println("Description: " + description);
        System.out.println("Severity: " + severity);
    }
}
