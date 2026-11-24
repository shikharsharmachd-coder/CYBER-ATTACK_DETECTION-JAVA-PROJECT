
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class Alert {

    private String alertId;
    private String ipAddress;
    private String threatType;
    private String description;
    private String status;
    private LocalDateTime timestamp;

    // Constructor
    public Alert(String ipAddress, String threatType,
                 String description) {

        this.alertId = UUID.randomUUID().toString()
                .substring(0, 8);

        this.ipAddress = ipAddress;
        this.threatType = threatType;
        this.description = description;
        this.status = "OPEN";
        this.timestamp = LocalDateTime.now();
    }

    // Getters
    public String getAlertId() {
        return alertId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getThreatType() {
        return threatType;
    }

    public String getDescription() {
        return description;
    }

    public String getStatus() {
        return status;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    // Display alert information
    public void displayAlert() {

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

        System.out.println("Alert ID: " + alertId);
        System.out.println("IP Address: " + ipAddress);
        System.out.println("Threat Type: " + threatType);
        System.out.println("Description: " + description);
        System.out.println("Status: " + status);
        System.out.println("Timestamp: "
                + timestamp.format(formatter));
    }
}
