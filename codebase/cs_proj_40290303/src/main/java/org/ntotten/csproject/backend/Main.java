/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

// The main class.
@SpringBootApplication
public class Main {
    private static final String CREATE_DOCUMENTS_TABLE = "CREATE TABLE IF NOT EXISTS documents" +
                                                                "(" +
                                                                "document_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                                                                "encrypted_file_name BLOB," +
                                                                "encrypted_data BLOB" +
                                                                ")";

    public static void main(String[] args) {
        initDB();
        SpringApplication.run(Main.class, args);
    }

    private static void initDB() {
        // Encapsulate connection and statement resources for better management
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:database/sse.db");
             Statement statement = connection.createStatement()) {
            System.out.println("Connection to SQLite database established.");
            // Create tables, handling errors with informative messages
            createTable(statement);
        } catch (SQLException e) {
            System.err.println("Error during database initialization: " + e.getMessage());
            throw new IllegalStateException("Database initialization failed", e);
        }
    }

    private static void createTable(Statement statement) throws SQLException {
        try {
            statement.execute(Main.CREATE_DOCUMENTS_TABLE);
            System.out.println("Table '" + "documents" + "' successfully created!");
        } catch (SQLException e) {
            System.err.println("Error creating table '" + "documents" + "': " + e.getMessage());
            if (!"table already exists".equalsIgnoreCase(e.getMessage().trim())) {
                throw e; // Rethrow if not a duplicate table error
            }
        }
    }
}
