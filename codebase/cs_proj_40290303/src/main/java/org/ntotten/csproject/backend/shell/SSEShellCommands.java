/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.shell;

import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.ntotten.csproject.backend.documentutil.DocumentUtility;
import org.ntotten.csproject.backend.crypto.Encryption;
import org.ntotten.csproject.backend.search.Search;
import org.ntotten.csproject.backend.search.ServerIndex;
import org.ntotten.csproject.backend.search.Trapdoor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.ntotten.csproject.backend.crypto.Encryption.checkKeys;
import static org.ntotten.csproject.backend.crypto.Encryption.loadKeysFromKeystore;

@ShellComponent
public class SSEShellCommands {

    @Autowired
    ShellHelper shellHelper;

    @Autowired
    InputReader inputReader;

    private static ArrayList<String> searchResults = new ArrayList<>();
    private static ArrayList<BigInteger> encryptedResults = new ArrayList<>();

    @ShellMethod(value = "This command generates the required encryption keys.", key = "generate-keys")
    public void keyGen() {
        try {
            Encryption.generateKeys();
            shellHelper.printSuccess("Encryption Keys generated!");
        } catch (Exception e) {
            shellHelper.printError("Error generating Encryption Keys!\n" + e.getMessage());
        }
    }

    @ShellMethod(value = "This command is used to upload a specific file.", key = "upload-file")
    public void uploadFile() {
        if (checkKeys(shellHelper)) {
            String path;
            do {
                path = inputReader.prompt("Enter the path to the file you wish to upload: ");

            } while (path.isEmpty());

            try {
                DocumentUtility.readFileFromDir(path, shellHelper);
            } catch (Exception e) {
                shellHelper.printError("Error uploading file: " + e.getMessage());
            }
        }
    }

    @ShellMethod(value = "This command is used to upload all files at a specified directory.", key = "upload-all-files")
    public void uploadFiles() {
        if (checkKeys(shellHelper)) {
            String dir;
            do {
                dir = inputReader.prompt("Enter the path to the files you wish to upload: ");
            } while (dir.isEmpty());

            try {
                DocumentUtility.readAllFilesFromDir(dir, shellHelper);
            } catch (Exception e) {
                shellHelper.printError("Error uploading files: " + e.getMessage());
            }
        }
    }

    @ShellMethod(value = "This command is used to search for the provided keyword.", key = "search")
    public void search() throws Exception {
        if (!DocumentUtility.getMapOfFilesToWordSets().isEmpty()) {
            searchResults.clear();
            encryptedResults.clear();
            ServerIndex.buildIndex();

            String keyWord = inputReader.prompt("Please enter the keyword you wish to search for: ");

            long searchStart = System.nanoTime();

            //encryptedResults = Search.multiThreadSearch(keyWord.toLowerCase());
            encryptedResults = Search.search(keyWord.toLowerCase());

            long searchEnd = System.nanoTime();
            double searchTimeMS = (searchEnd - searchStart) / 1000000.0;

            shellHelper.printInfo("Search completed in " + searchTimeMS + " ms");

            assert encryptedResults != null : "No matches! Null search results.";

            if (!encryptedResults.isEmpty()) {
                shellHelper.printSuccess("Search was successful!");
                shellHelper.printInfo("Matching files:");
                for (BigInteger encrypted : encryptedResults) {
                    byte[] encryptedBytes = encrypted.toByteArray();
                    String plaintext = new String(Encryption.decryptString(encryptedBytes, Encryption.getOwnerKey()), UTF_8);
                    searchResults.add(plaintext);
                    shellHelper.printInfo(plaintext);
                }
            } else {
                shellHelper.printInfo("Sorry! No results found.");
            }
        } else {
            shellHelper.printWarning("Cannot perform search - Document collection is empty!");
        }
    }

    @ShellMethod(value = "This command is used to download a file from the search results.", key = "download-file")
    public void downloadFile() throws Exception {
        if (!searchResults.isEmpty()) {
            shellHelper.printInfo("Search Results:");
            for (int i = 0; i < searchResults.size(); i++) {
                shellHelper.printInfo((i + 1) + ". " + searchResults.get(i));
            }

            try {
                int fileChoice = Integer.parseInt(inputReader.prompt("Please select the file you wish to download: "));
                byte[] fileToDownload = encryptedResults.get(fileChoice - 1).toByteArray();
                String fileName = searchResults.get(fileChoice - 1);
                DocumentUtility.writeToFile(fileToDownload, fileName, Encryption.getOwnerKey());
            } catch (NumberFormatException e) {
                shellHelper.printWarning("Please enter a valid integer from the search results!");
            }
        } else {
            shellHelper.printWarning("There are no search results to retrieve from yet!");
        }
    }

    @ShellMethod(value = "This command is used to export your encryption keys for future sessions.", key = "export-keys")
    public void exportKeys() {
        //inputReader.prompt("Please enter a password for your keystore: ", "*", false);
        if (checkKeys(shellHelper)) {
            exportEncryptionKeys(shellHelper);
        } else {
            shellHelper.printWarning("No keys to export!");
        }
    }

    @ShellMethod(value = "This command is used to import your encryption keys from past sessions.", key = "import-keys")
    public void importKeys() throws IOException {
        Terminal terminal = TerminalBuilder.builder().build();
        LineReader lineReader = LineReaderBuilder.builder().terminal(terminal).build();
        String pathToKeyStore = inputReader.prompt("Please enter the path to your keystore: ");
        if (!pathToKeyStore.isEmpty() && Files.exists(Paths.get(pathToKeyStore))) {
            char[] keyStorePassword = lineReader.readLine("Please enter your keystore password: ", '*').toCharArray();
            try {
                loadKeysFromKeystore(pathToKeyStore, keyStorePassword);
                shellHelper.printSuccess("Keystore successfully imported!");
            } catch (Exception e) {
                shellHelper.printError("Error loading keys from keystore: " + e.getMessage());
            }

        } else {
            shellHelper.printWarning("No keystore found!");
        }
    }

    private static void exportEncryptionKeys(ShellHelper shellHelper) {
        try {
            shellHelper.printInfo("Exporting Encryption Keys to secure Key Store...");

            Terminal terminal = TerminalBuilder.builder().build();
            LineReader lineReader = LineReaderBuilder.builder().terminal(terminal).build();

            boolean validPassword = false; // Default valid password to false.
            String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=£!*_])(?=\\S+$).{8,30}$"; // Set regex to validate password.

            while (!validPassword) {
                String password = lineReader.readLine("Please enter a secure password for key storage (You may wish to store this in a password manager of your choosing!):\n", '*');
                validPassword = password.matches(regex);
                if (validPassword) {
                    Encryption.exportKeysToKeyStore(password.toCharArray());
                } else {
                    shellHelper.printError("Invalid password!");
                }
            }
        } catch (Exception e) {
            shellHelper.printError("Error exporting Encryption Keys!\n" + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
