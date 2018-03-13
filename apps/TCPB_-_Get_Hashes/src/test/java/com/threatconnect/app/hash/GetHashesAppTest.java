package com.threatconnect.app.hash;

import com.threatconnect.app.addons.util.config.install.StandardPlaybookType;
import com.threatconnect.app.apps.AppConfig;
import com.threatconnect.apps.playbooks.test.config.PlaybooksTestConfiguration;
import com.threatconnect.apps.playbooks.test.orc.PlaybooksOrchestrationBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

public class GetHashesAppTest {
    @Before
    public void setUp()
    {
        //register the inmemory database
        PlaybooksTestConfiguration.getInstance().registerEmbeddedDBService();

        //Get the global config
        AppConfig ac = PlaybooksTestConfiguration.getInstance().getGlobalAppConfig();

        //doesn't drive anything during junit test as there is a log4j2.xml file existing in playbooks-test
        //that sets the global level to info which you can change if needed for testing.
        ac.set(AppConfig.TC_LOG_LEVEL, "debug");

        //set base params
        ac.set(AppConfig.TC_TEMP_PATH, "./AppOutput");
        ac.set(AppConfig.TC_LOG_PATH,  "./AppOutput");
        ac.set(AppConfig.TC_OUT_PATH,  "./AppOutput");
        ac.set(AppConfig.TC_API_PATH,  "https://localhost:8443/api");

    }

    @Test
    public void testSingleStringInput() throws Exception
    {
        PlaybooksOrchestrationBuilder.runApp(GetHashesApp.class)
                .withPlaybookParam()
                .asString(GetHashesApp.INPUT_CONTENT, "foobar")
                .then().onSuccess().assertOutput()
                .assertEquals(GetHashesApp.OUTPUT_MD5, StandardPlaybookType.String, "3858F62230AC3C915F300C664312C63F")
                .assertEquals(GetHashesApp.OUTPUT_SHA1, StandardPlaybookType.String, "8843D7F92416211DE9EBB963FF4CE28125932878")
                .assertEquals(GetHashesApp.OUTPUT_SHA256, StandardPlaybookType.String, "C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2")
                .assertMessageTcContains("Successfully hashed content.")
                .then().build().run();
    }


    @Test
    public void testSingleBinaryInput() throws Exception
    {
        PlaybooksOrchestrationBuilder.runApp(GetHashesApp.class)
                .withPlaybookParam()
                .asBinary(GetHashesApp.INPUT_CONTENT, "foobar".getBytes())
                .then().onSuccess().assertOutput()
                .assertEquals(GetHashesApp.OUTPUT_MD5, StandardPlaybookType.String, "3858F62230AC3C915F300C664312C63F")
                .assertEquals(GetHashesApp.OUTPUT_SHA1, StandardPlaybookType.String, "8843D7F92416211DE9EBB963FF4CE28125932878")
                .assertEquals(GetHashesApp.OUTPUT_SHA256, StandardPlaybookType.String, "C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2")
                .assertMessageTcContains("Successfully hashed content.")
                .runTest(GetHashesApp.OUTPUT_MD5, StandardPlaybookType.String, o -> {
                    System.out.println(o);
                    return true;
                })
                .runTest(GetHashesApp.OUTPUT_SHA1, StandardPlaybookType.String, o -> {
                    System.out.println(o);
                    return true;
                })
                .runTest(GetHashesApp.OUTPUT_SHA256, StandardPlaybookType.String, o -> {
                    System.out.println(o);
                    return true;
                })
                .then().build().run();
    }

    @Test
    public void testMultipleStringInput() throws Exception
    {
        PlaybooksOrchestrationBuilder.runApp(GetHashesApp.class)
                .withPlaybookParam()
                .asStringList(GetHashesApp.INPUT_CONTENT, Arrays.asList("foobar", "bashbang"))
                .then().onSuccess().assertOutput()
                .assertStringArrayEquals(GetHashesApp.OUTPUT_MD5, "StringArray",
                        Arrays.asList("3858F62230AC3C915F300C664312C63F", "B2AA44DECEC7D03EBE553110B16BB26F"))
                .assertStringArrayEquals(GetHashesApp.OUTPUT_SHA1, "StringArray",
                        Arrays.asList("8843D7F92416211DE9EBB963FF4CE28125932878", "786A316429228F75C4C2CC81A8780DA3E05FBDE0"))
                .assertStringArrayEquals(GetHashesApp.OUTPUT_SHA256, "StringArray",
                        Arrays.asList("C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2",
                                "3598E77DD635206DE2D96ACDC6C1525513E2199B2F2EF0B2A3D3E3300B44DE75"))
                .assertMessageTcContains("Successfully hashed content.")
                .then().build().run();
    }

    @Test
    public void testMultipleBinaryInput() throws Exception
    {
        PlaybooksOrchestrationBuilder.runApp(GetHashesApp.class)
                .withPlaybookParam()
                .asBinaryArray(GetHashesApp.INPUT_CONTENT, new byte[][]{"foobar".getBytes(), "bashbang".getBytes()})
                .then().onSuccess().assertOutput()
                .assertStringArrayEquals(GetHashesApp.OUTPUT_MD5, "StringArray",
                        Arrays.asList("3858F62230AC3C915F300C664312C63F", "B2AA44DECEC7D03EBE553110B16BB26F"))
                .assertStringArrayEquals(GetHashesApp.OUTPUT_SHA1, "StringArray",
                        Arrays.asList("8843D7F92416211DE9EBB963FF4CE28125932878", "786A316429228F75C4C2CC81A8780DA3E05FBDE0"))
                .assertStringArrayEquals(GetHashesApp.OUTPUT_SHA256, "StringArray",
                        Arrays.asList("C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2",
                                "3598E77DD635206DE2D96ACDC6C1525513E2199B2F2EF0B2A3D3E3300B44DE75"))
                .assertMessageTcContains("Successfully hashed content.")
                .then().build().run();
    }
}
