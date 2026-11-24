
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class LogDAO {

    // Save a security log into MySQL
    public static void saveLog(LogEntry log, String detectionResult) {

        String sql = """
            INSERT INTO security_logs
            (ip_address, event_type, description, severity, detection_result)
            VALUES (?, ?, ?, ?, ?)
            """;

        try (Connection connection = DatabaseConnection.getConnection()) {

            if (connection == null) {
                System.out.println("Database connection unavailable.");
                return;
            }

            try (PreparedStatement statement = connection.prepareStatement(sql)) {

                statement.setString(1, log.getIpAddress());
                statement.setString(2, log.getEventType());
                statement.setString(3, log.getDescription());
                statement.setString(4, log.getSeverity());
                statement.setString(5, detectionResult);

                statement.executeUpdate();

                System.out.println("Security log saved to MySQL!");
            }

        } catch (SQLException e) {
            System.out.println("Failed to save security log: " + e.getMessage());
        }
    }

    // Save a generated alert into MySQL
    public static void saveAlert(Alert alert) {

        String sql = """
            INSERT INTO alerts
            (alert_id, ip_address, threat_type, description, status)
            VALUES (?, ?, ?, ?, ?)
            """;

        try (Connection connection = DatabaseConnection.getConnection()) {

            if (connection == null) {
                System.out.println("Database connection unavailable.");
                return;
            }

            try (PreparedStatement statement = connection.prepareStatement(sql)) {

                statement.setString(1, alert.getAlertId());
                statement.setString(2, alert.getIpAddress());
                statement.setString(3, alert.getThreatType());
                statement.setString(4, alert.getDescription());
                statement.setString(5, alert.getStatus());

                statement.executeUpdate();

                System.out.println("Security alert saved to MySQL!");
            }

        } catch (SQLException e) {
            System.out.println("Failed to save alert: " + e.getMessage());
        }
    }

    // Retrieve the latest 100 security logs
    public static String getRecentLogs() throws SQLException {

        String sql = """
            SELECT log_id, ip_address, event_type,
                   description, severity, detection_result, created_at
            FROM security_logs
            ORDER BY log_id DESC
            LIMIT 100
            """;

        StringBuilder json = new StringBuilder("[");
        boolean first = true;

        try (Connection connection = DatabaseConnection.getConnection()) {

            if (connection == null) {
                throw new SQLException("Database connection unavailable.");
            }

            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rs = statement.executeQuery()) {

                while (rs.next()) {

                    if (!first) {
                        json.append(",");
                    }

                    first = false;

                    json.append("{")
                        .append("\"log_id\":").append(rs.getInt("log_id")).append(",")
                        .append("\"ip_address\":").append(quote(rs.getString("ip_address"))).append(",")
                        .append("\"event_type\":").append(quote(rs.getString("event_type"))).append(",")
                        .append("\"description\":").append(quote(rs.getString("description"))).append(",")
                        .append("\"severity\":").append(quote(rs.getString("severity"))).append(",")
                        .append("\"detection_result\":").append(quote(rs.getString("detection_result"))).append(",")
                        .append("\"created_at\":").append(quote(rs.getString("created_at")))
                        .append("}");
                }
            }
        }

        return json.append("]").toString();
    }

    // Retrieve the latest 100 security alerts
    public static String getRecentAlerts() throws SQLException {

        String sql = """
            SELECT alert_id, ip_address, threat_type,
                   description, status, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT 100
            """;

        StringBuilder json = new StringBuilder("[");
        boolean first = true;

        try (Connection connection = DatabaseConnection.getConnection()) {

            if (connection == null) {
                throw new SQLException("Database connection unavailable.");
            }

            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rs = statement.executeQuery()) {

                while (rs.next()) {

                    if (!first) {
                        json.append(",");
                    }

                    first = false;

                    json.append("{")
                        .append("\"alert_id\":").append(quote(rs.getString("alert_id"))).append(",")
                        .append("\"ip_address\":").append(quote(rs.getString("ip_address"))).append(",")
                        .append("\"threat_type\":").append(quote(rs.getString("threat_type"))).append(",")
                        .append("\"description\":").append(quote(rs.getString("description"))).append(",")
                        .append("\"status\":").append(quote(rs.getString("status"))).append(",")
                        .append("\"created_at\":").append(quote(rs.getString("created_at")))
                        .append("}");
                }
            }
        }

        return json.append("]").toString();
    }

    // Safely format Java strings as JSON strings
    private static String quote(String value) {

        if (value == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder("\"");

        for (char c : value.toCharArray()) {

            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (c < 32) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
                }
            }
        }

        return result.append("\"").toString();
    }

    // Retrieve dashboard statistics from MySQL
    public static String getDashboardStats() throws SQLException {

        String sql = """
            SELECT
                (SELECT COUNT(*) FROM security_logs) AS total_events,

                (SELECT COUNT(*)
                 FROM security_logs
                 WHERE detection_result LIKE 'SUSPICIOUS%') AS threats_detected,

                (SELECT COUNT(DISTINCT ip_address)
                 FROM security_logs
                 WHERE detection_result LIKE 'SUSPICIOUS%') AS flagged_ips,

                (SELECT COUNT(*)
                 FROM alerts
                 WHERE UPPER(status) = 'RESOLVED') AS resolved_incidents
            """;

        try (Connection connection = DatabaseConnection.getConnection()) {

            if (connection == null) {
                throw new SQLException("Database connection unavailable.");
            }

            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rs = statement.executeQuery()) {

                if (rs.next()) {

                    return "{"
                        + "\"total_events\":" + rs.getInt("total_events") + ","
                        + "\"threats_detected\":" + rs.getInt("threats_detected") + ","
                        + "\"flagged_ips\":" + rs.getInt("flagged_ips") + ","
                        + "\"resolved_incidents\":" + rs.getInt("resolved_incidents")
                        + "}";
                }
            }
        }

        throw new SQLException("Unable to retrieve dashboard statistics.");
    }
    // Mark an incident as resolved in MySQL
public static boolean resolveAlert(String alertId) throws SQLException {

    String sql = """
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
        """;

    try (Connection connection = DatabaseConnection.getConnection()) {

        if (connection == null) {
            throw new SQLException("Database connection unavailable.");
        }

        try (PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, "RESOLVED");
            statement.setString(2, alertId);

            int rowsUpdated = statement.executeUpdate();

            return rowsUpdated > 0;
        }
    }
}
}
