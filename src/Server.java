
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class Server {

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(
                new InetSocketAddress(8080), 0
        );

        // API 1: Check server status
        server.createContext("/api/status", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            sendResponse(exchange, 200,
                    "{\"status\":\"running\",\"message\":\"CyberGuard backend is working!\"}");
        });

        // API 2: Submit and retrieve security logs
        server.createContext("/api/logs", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {

                try {
                    String logs = LogDAO.getRecentLogs();
                    sendResponse(exchange, 200, logs);

                } catch (SQLException e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to retrieve security logs\"}");
                }

                return;
            }

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            try {

                String requestBody = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> data = new HashMap<>();

                for (String pair : requestBody.split("&")) {

                    String[] parts = pair.split("=", 2);

                    if (parts.length == 2) {

                        String key = URLDecoder.decode(
                                parts[0], StandardCharsets.UTF_8
                        );

                        String value = URLDecoder.decode(
                                parts[1], StandardCharsets.UTF_8
                        );

                        data.put(key, value);
                    }
                }

                String ip = data.getOrDefault("ipAddress", "").trim();
                String type = data.getOrDefault("eventType", "").trim();
                String description = data.getOrDefault("description", "").trim();
                String severity = data.getOrDefault("severity", "").trim();

                if (ip.isBlank() || type.isBlank()
                        || description.isBlank() || severity.isBlank()) {

                    sendResponse(exchange, 400,
                            "{\"error\":\"All fields are required\"}");
                    return;
                }

                LogEntry log = new LogEntry(
                        ip, type, description, severity
                );

                String detectionResult = DetectionEngine.analyze(log);

                LogDAO.saveLog(log, detectionResult);

                if (detectionResult.startsWith("SUSPICIOUS")) {

                    Alert alert = new Alert(
                            ip,
                            "Security Threat",
                            detectionResult
                    );

                    alert.displayAlert();
                    LogDAO.saveAlert(alert);
                }

                System.out.println("\n===== NEW SECURITY LOG =====");
                log.displayLog();
                System.out.println("Detection Result: " + detectionResult);
                System.out.println("============================");

                String response = "{"
                        + "\"status\":\"success\","
                        + "\"message\":\"Security log processed\","
                        + "\"detection\":" + jsonQuote(detectionResult)
                        + "}";

                sendResponse(exchange, 200, response);

            } catch (Exception e) {

                e.printStackTrace();

                sendResponse(exchange, 400,
                        "{\"error\":\"Invalid request data\"}");
            }
        });

        // API 3: Retrieve dashboard statistics
        server.createContext("/api/summary", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            try {

                String summary = LogDAO.getDashboardStats();

                sendResponse(exchange, 200, summary);

            } catch (SQLException e) {

                e.printStackTrace();

                sendResponse(exchange, 500,
                        "{\"error\":\"Unable to retrieve dashboard statistics\"}");
            }
        });

        // API 4: Retrieve alerts and resolve incidents
        server.createContext("/api/alerts", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            String requestMethod = exchange.getRequestMethod();
            String requestPath = exchange.getRequestURI().getPath();

            // GET /api/alerts
            if (requestMethod.equalsIgnoreCase("GET")) {

                if (!requestPath.equals("/api/alerts")) {
                    sendResponse(exchange, 404,
                            "{\"error\":\"API endpoint not found\"}");
                    return;
                }

                try {

                    String alerts = LogDAO.getRecentAlerts();
                    sendResponse(exchange, 200, alerts);

                } catch (SQLException e) {

                    e.printStackTrace();

                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to retrieve security alerts\"}");
                }

                return;
            }

            // POST /api/alerts/{alertId}/resolve
            if (requestMethod.equalsIgnoreCase("POST")) {

                String prefix = "/api/alerts/";
                String suffix = "/resolve";

                if (!requestPath.startsWith(prefix)
                        || !requestPath.endsWith(suffix)) {

                    sendResponse(exchange, 404,
                            "{\"error\":\"API endpoint not found\"}");
                    return;
                }

                String encodedAlertId = requestPath.substring(
                        prefix.length(),
                        requestPath.length() - suffix.length()
                );

                if (encodedAlertId.isBlank()
                        || encodedAlertId.contains("/")) {

                    sendResponse(exchange, 400,
                            "{\"error\":\"Invalid alert ID\"}");
                    return;
                }

                try {

                    String alertId = URLDecoder.decode(
                            encodedAlertId,
                            StandardCharsets.UTF_8
                    );

                    boolean resolved = LogDAO.resolveAlert(alertId);

                    if (!resolved) {

                        sendResponse(exchange, 404,
                                "{\"error\":\"Alert not found\"}");
                        return;
                    }

                    sendResponse(exchange, 200,
                            "{"
                                    + "\"status\":\"success\","
                                    + "\"message\":\"Incident resolved successfully\""
                                    + "}"
                    );

                } catch (SQLException e) {

                    e.printStackTrace();

                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to resolve incident\"}");
                }

                return;
            }

            sendResponse(exchange, 405,
                    "{\"error\":\"Method not allowed\"}");
        });

        server.start();

        System.out.println("==================================");
        System.out.println(" CyberGuard Backend Started!");
        System.out.println(" http://localhost:8080");
        System.out.println("==================================");
    }

    // Allow frontend development server to communicate with Java
    private static void addCorsHeaders(HttpExchange exchange) {

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Origin", "*"
        );

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Methods", "GET, POST, OPTIONS"
        );

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Headers", "Content-Type"
        );
    }

    // Handle browser preflight requests
    private static boolean handleOptions(HttpExchange exchange)
            throws IOException {

        if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {

            exchange.sendResponseHeaders(204, -1);
            exchange.close();

            return true;
        }

        return false;
    }

    // Safely format a Java string as JSON
    private static String jsonQuote(String value) {

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

    // Common method for sending HTTP responses
    private static void sendResponse(
            HttpExchange exchange,
            int statusCode,
            String response
    ) throws IOException {

        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type", "application/json; charset=UTF-8"
        );

        exchange.sendResponseHeaders(statusCode, responseBytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
