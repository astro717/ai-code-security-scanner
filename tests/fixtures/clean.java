// clean.java — fixture file for Java scanner integration tests.
// Each snippet is the safe equivalent of a pattern the scanner targets.
// The scanner should produce zero findings for this file.

import java.sql.*;
import java.io.*;
import java.security.*;

public class CleanApp {

    // Safe SQL: parameterised query — no injection risk
    public ResultSet getUser(Connection conn, String username) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, username);
        return stmt.executeQuery();
    }

    // Safe command execution: no string concatenation, fixed command
    public Process runCommand() throws IOException {
        ProcessBuilder pb = new ProcessBuilder("ls", "-la");
        return pb.start();
    }

    // Safe secret: loaded from environment
    private String apiKey = System.getenv("API_KEY");

    // Safe hashing: SHA-256
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes());
    }

    // Safe file read: fixed path, no user input
    public String readConfig() throws IOException {
        File f = new File("/etc/app/config.json");
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    // Safe random: SecureRandom
    public String generateToken() {
        java.security.SecureRandom rng = new java.security.SecureRandom();
        return String.valueOf(rng.nextLong());
    }
}
