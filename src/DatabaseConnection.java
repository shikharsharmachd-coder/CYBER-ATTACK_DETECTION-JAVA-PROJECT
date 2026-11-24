
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {

    // MySQL connection details
    private static final String URL =
            "jdbc:mysql://localhost:3306/cyberguard_db";

    private static final String USER = "root";

    // Replace this with your actual MySQL password
    private static final String PASSWORD = "Shikharr@003";

    // Establish database connection
    public static Connection getConnection() {

        try {
            Connection connection = DriverManager.getConnection(
                    URL, USER, PASSWORD
            );

            System.out.println("MySQL Connected Successfully!");

            return connection;

        } catch (SQLException e) {

            System.out.println("Database Connection Failed!");
            System.out.println(e.getMessage());

            return null;
        }
    }
}
