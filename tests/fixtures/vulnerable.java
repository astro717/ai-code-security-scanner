// vulnerable.java — fixture file for Java scanner integration tests.
// Each snippet intentionally triggers a different Java vulnerability detector.
// DO NOT compile or run this code — it is test data only.

import java.sql.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;

public class VulnerableApp {

    // SQL_INJECTION: string concatenation in JDBC query
    public ResultSet getUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }

    // COMMAND_INJECTION: Runtime.exec with string concatenation
    public void runCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("sh -c " + userInput);
    }

    // SECRET_HARDCODED: API key stored as a literal string
    private String apiKey = "sk-abcdef1234567890abcdef1234567890";

    // WEAK_CRYPTO: MD5 usage
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // PATH_TRAVERSAL: File constructor with user input from request
    public String readFile(javax.servlet.http.HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        File f = new File("/var/data/" + filename);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    // INSECURE_RANDOM: java.util.Random for token generation
    public String generateToken() {
        java.util.Random rng = new Random();
        return String.valueOf(rng.nextLong());
    }

    // UNSAFE_DESERIALIZATION: ObjectInputStream.readObject
    public Object deserialize(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }
}
