package com.threatconnect.app.hash;

import com.threatconnect.app.apps.ExitStatus;
import com.threatconnect.app.playbooks.app.PlaybooksApp;
import com.threatconnect.app.playbooks.app.PlaybooksAppConfig;
import com.threatconnect.app.playbooks.content.accumulator.ContentException;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Playbook app that generates hashes for a given String, Binary, StringArray, or BinaryArray input.
 *
 * @author Chris Blades
 * @version 1.0.0
 */
public class GetHashesApp extends PlaybooksApp {
    static final String INPUT_CONTENT = "content";
    static final String OUTPUT_MD5 = "md5";
    static final String OUTPUT_SHA1 = "sha1";
    static final String OUTPUT_SHA256 = "sha256";

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GetHashesApp.class);

    private MessageDigest md5Digest;
    private MessageDigest sha1Digest;
    private MessageDigest sha256Digest;

    @Override
    protected ExitStatus execute(PlaybooksAppConfig playbooksAppConfig) throws Exception {
        md5Digest = MessageDigest.getInstance("MD5");
        sha1Digest = MessageDigest.getInstance("SHA-1");
        sha256Digest = MessageDigest.getInstance("SHA-256");

        List<byte[]> contents = readContents();


        List<String> md5s;
        List<String> sha1s;
        List<String> sha256s;

        List<Hashes> hashes =
                contents.stream()
                        .map(this::getHashes)
                        .collect(Collectors.toList());

        if (hashes.size() == 1) {
            if (isOutputParamExpected(OUTPUT_MD5, "String")) {
                writeStringContent(OUTPUT_MD5, hashes.get(0).md5);
            }
            if (isOutputParamExpected(OUTPUT_SHA1, "String")) {
                writeStringContent(OUTPUT_SHA1, hashes.get(0).sha1);
            }
            if (isOutputParamExpected(OUTPUT_SHA256, "String")) {
                writeStringContent(OUTPUT_SHA256, hashes.get(0).sha256);
            }
        }

        if (isOutputParamExpected(OUTPUT_MD5, "StringArray")) {
            writeStringListContent(OUTPUT_MD5, hashes.stream().map(Hashes::getMd5).collect(Collectors.toList()));
        }
        if (isOutputParamExpected(OUTPUT_SHA1, "StringArray")) {
            writeStringListContent(OUTPUT_SHA1, hashes.stream().map(Hashes::getSha1).collect(Collectors.toList()));
        }
        if (isOutputParamExpected(OUTPUT_SHA256, "StringArray")) {
            writeStringListContent(OUTPUT_SHA256, hashes.stream().map(Hashes::getSha256).collect(Collectors.toList()));
        }

        writeMessageTc("Successfully hashed content.");
        return ExitStatus.Success;

    }

    private Hashes getHashes(byte[] bytes) {
        String md5 = DatatypeConverter.printHexBinary(DigestUtils.md5(bytes));
        String sha1 = DatatypeConverter.printHexBinary(DigestUtils.sha1(bytes));
        String sha256 = DatatypeConverter.printHexBinary(DigestUtils.sha256(bytes));

        Hashes hashes = new Hashes();
        hashes.md5 = md5;
        hashes.sha1 = sha1;
        hashes.sha256 = sha256;

        return hashes;
    }

    private List<byte[]> readContents() throws ContentException {
        String contentType = getPlaybookTypeOfInputParam(INPUT_CONTENT);
        List<byte[]> contents = Collections.EMPTY_LIST;
        switch (contentType.toUpperCase()) {
            case "STRING":
                contents = Arrays.asList(readStringContent(INPUT_CONTENT).getBytes());
                break;
            case "STRINGARRAY":
                contents = readStringListContent(INPUT_CONTENT)
                        .stream()
                        .map(String::getBytes)
                        .collect(Collectors.toList());
                break;
            case "BINARY":
                contents = Arrays.asList(readBinaryContent(INPUT_CONTENT));
                break;
            case "BINARYARRAY":
                contents = Arrays.asList(readBinaryArrayContent(INPUT_CONTENT));
                break;
        }

        return contents;
    }


    private class Hashes {
        String md5;
        String sha1;
        String sha256;

        public String getMd5() {
            return md5;
        }

        public String getSha1() {
            return sha1;
        }

        public String getSha256() {
            return sha256;
        }
    }
}
