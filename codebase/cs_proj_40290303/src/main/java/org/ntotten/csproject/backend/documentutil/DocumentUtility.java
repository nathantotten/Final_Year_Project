/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.documentutil;

import org.ntotten.csproject.backend.crypto.Encryption;
import org.ntotten.csproject.backend.shell.ShellHelper;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.ntotten.csproject.backend.crypto.Encryption.checkKeys;

public class DocumentUtility{
    private static final HashMap<byte[], HashSet<String>> mapOfFilesToWordSets = new HashMap<>();
    private static final HashSet<String> allUniqueWords = new HashSet<>();

    private static boolean isValidFilePath(String filePath) {
        try {
            Path path = Paths.get(filePath);
            return Files.exists(path);
        } catch (InvalidPathException | NullPointerException ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }

    private static boolean isValidDir(String dirPath) {
        try {
            Path directory = Paths.get(dirPath);
            return Files.isDirectory(directory);
        } catch (InvalidPathException | NullPointerException ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }

    public static void readFileFromDir(String pathStr, ShellHelper shellHelper) throws NoSuchAlgorithmException {

        if (!isValidFilePath(pathStr)) {
            System.err.println(pathStr + " is not a valid file path!");
            return;
        }

        Path path = Paths.get(pathStr);

        // Check filepath is valid text file
        if (!Files.isRegularFile(path) || !path.toString().toLowerCase().endsWith(".txt")) {
            System.err.println(path.getFileName() + " is not a valid .txt file!");
            return;
        }

        StringBuilder stringBuilder = new StringBuilder();
        HashSet<String> fileSpecificWordSet = new HashSet<>();

        try ( BufferedReader br = Files.newBufferedReader(path) ) {

            while (br.ready()) {
                String line = br.readLine();
                stringBuilder.append(line).append("\n");
                String[] words = line.replaceAll("[^\\w\\s]", "").toLowerCase().split("\\s+");
                allUniqueWords.addAll(Arrays.asList(words));
                fileSpecificWordSet.addAll(Arrays.asList(words));
            }

            // Encrypt the string builder object (that at this point contains all the lines of the file) using the data owner key
            String fileContent = stringBuilder.toString();

            long encryptionStart = System.nanoTime();

            byte[] encryptedContent = Encryption.encryptString(fileContent, Encryption.getOwnerKey(), Encryption.generateInitialisationVector());

            long encryptionEnd = System.nanoTime();
            double timeTakenMS = (encryptionEnd - encryptionStart) / 1000000.0;
            shellHelper.printInfo("File Encryption took: " + timeTakenMS + " ms");

            byte[] encryptedFileName = Encryption.encryptString(path.getFileName().toString(), Encryption.getOwnerKey(), Encryption.generateInitialisationVector());

            // This map of fileNames to file-specific word sets is used for generating the Server Index.
            mapOfFilesToWordSets.put(encryptedFileName, fileSpecificWordSet);

            // Here, the database stands as an analogue for the server - storing the encrypted files.
            writeEncryptedFileDataToDB(encryptedFileName, encryptedContent);
            shellHelper.printSuccess("File " + path.getFileName() + " successfully uploaded!");

        } catch ( Exception ex ) {
            System.err.println("Error reading file : " + ex.getMessage());
            shellHelper.printError("Error reading file : " + ex.getMessage());
            ex.printStackTrace();
        }
    }



    public static void readAllFilesFromDir(String pathStr, ShellHelper shellHelper) {

        if (!isValidDir(pathStr)) {
            System.err.println(pathStr + " is not a valid directory!");
            return;
        }

        Path path = Paths.get(pathStr);

        try (Stream<Path> filePaths = Files.list(path)) {
            filePaths.forEach(filePath -> {
                try {
                    readFileFromDir(filePath.toString(), shellHelper);
                } catch (NoSuchAlgorithmException e) {
                    System.err.println(e.getMessage());
                }
            });
        } catch (IOException ex) {
            System.err.println("Unable to read files from directory : " + ex.getMessage());
            shellHelper.printError("Unable to read files from directory : " + ex.getMessage());
        }
    }

    public static HashSet<String> getAllUniqueWords() {
        return allUniqueWords;
    }

    public static HashMap<byte[], HashSet<String>> getMapOfFilesToWordSets() {
        return mapOfFilesToWordSets;
    }

    private static void writeEncryptedFileDataToDB(byte[] fileName, byte[] encryptedFile) {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:database/sse.db");
             PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO documents (encrypted_file_name, encrypted_data) VALUES (?, ?)")) {

            preparedStatement.setBytes(1, fileName);
            preparedStatement.setBytes(2, encryptedFile);
            preparedStatement.executeUpdate();

        } catch (SQLException ex) {
            System.err.println("Error storing encrypted file data : " + ex.getMessage());
        }
    }

    private static byte[] retrieveEncryptedFileDataFromDB(byte[] encryptedFileName) {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:database/sse.db");
             PreparedStatement preparedStatement = connection.prepareStatement("SELECT encrypted_data FROM documents WHERE encrypted_file_name = ?")) {
            preparedStatement.setBytes(1, encryptedFileName);
            ResultSet encryptedFile = preparedStatement.executeQuery();
            return encryptedFile.getBytes(1);
        } catch (SQLException ex) {
            System.err.println("Error retrieving encrypted file data");
            return null;
        }
    }

    public static void writeToFile(byte[] encryptedFileName, String fileName, SecretKey key) throws Exception {
        String userHome = System.getProperty("user.home");
        String downloadsDirectory = userHome + "/Downloads/";

        long startTime = System.nanoTime();

        String content = new String(Encryption.decryptString(retrieveEncryptedFileDataFromDB(encryptedFileName), key), UTF_8);

        long endTime = System.nanoTime();
        double timeTakenMS = (endTime - startTime) / 1000000.0;
        System.err.println("Time taken to decrypt file: " + timeTakenMS + " ms");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(downloadsDirectory + fileName))) {
            writer.write(content);
            System.out.println("Data has been written to the file.");
        } catch (IOException e) {
            System.err.println("An error occurred while writing to the file: " + e.getMessage());
        }
    }
}
