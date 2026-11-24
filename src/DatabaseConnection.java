
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {

    private static final String URL =
            "jdbc:mysql://localhost:3306/cyberguard_db";

    private static final String USER =
            System.getenv("DB_USER");

    private static final String PASSWORD =
            System.getenv("DB_PASSWORD");

    public static Connection getConnection() {

        if (USER == null || PASSWORD == null) {
            System.out.println("Database credentials are missing!");
            System.out.println("Please configure DB_USER and DB_PASSWORD.");
            return null;
        }

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
