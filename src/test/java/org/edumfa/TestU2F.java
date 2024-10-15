/*
 * * License:  AGPLv3
 * * This file is part of eduMFA java client. eduMFA java client is a fork of privacyIDEA java client.
 * * Copyright (c) 2024 eduMFA Project-Team
 * * Previous authors of the PrivacyIDEA java client:
 * *
 * * NetKnights GmbH
 * * nils.behlen@netknights.it
 * * lukas.matusiewicz@netknights.it
 * *
 * * This code is free software; you can redistribute it and/or
 * * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * * License as published by the Free Software Foundation; either
 * * version 3 of the License, or any later version.
 * *
 * * This code is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 * *
 * * You should have received a copy of the GNU Affero General Public
 * * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */
package org.edumfa;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.edumfa.EMConstants.TOKEN_TYPE_U2F;

public class TestU2F
{
    private ClientAndServer mockServer;
    private EduMFA eduMFA;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void testTriggerU2F()
    {
        String u2fSignRequest = "{" + "\"appId\":\"https://ttype.u2f\"," +
                                "\"challenge\":\"TZKiB0VFFMFsnlz00lF5iCqtQduDJf56AeJAY_BT4NU\"," +
                                "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQJYu4G5qB9l7ScjRRxA-M35cTH-uHWyMEpxs4WBzbkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                "\"version\":\"U2F_V2\"" + "}";

        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&pass=test"))
                  .respond(HttpResponse.response().withBody(Utils.triggerU2FSuccess()));

        EMResponse response = eduMFA.validateCheck("Test", "test");

        assertEquals(1, response.id);
        assertEquals("Please confirm with your U2F token (Yubico U2F EE Serial 61730834)", response.message);
        assertEquals(0, response.otpLength);
        assertEquals("U2F00014651", response.serial);
        assertEquals("u2f", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.6.3", response.emVersion);
        assertEquals("rsa_sha256_pss:3e51d814...dccd5694b8c15943e37e1", response.signature);
        assertTrue(response.status);
        assertFalse(response.value);

        Optional<Challenge> opt = response.multichallenge.stream()
                                                         .filter(challenge -> TOKEN_TYPE_U2F.equals(challenge.getType()))
                                                         .findFirst();
        if (opt.isPresent())
        {
            Challenge a = opt.get();
            if (a instanceof U2F)
            {
                U2F b = (U2F) a;
                String trimmedRequest = u2fSignRequest.replaceAll("\n", "").replaceAll(" ", "");
                assertEquals(trimmedRequest, b.signRequest());
            }
            else
            {
                fail();
            }
        }
        else
        {
            fail();
        }
    }

    @Test
    public void testSuccess()
    {
        String username = "Test";

        String u2fSignResponse = "{\"clientData\":\"eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ\"," + "\"errorCode\":0," +
                                 "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                 "\"signatureData\":\"AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg\"}";

        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&transaction_id=16786665691788289392&pass=" +
                                             "&clientdata=eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ" +
                                             "&signaturedata=AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        Map<String, String> header = new HashMap<>();
        header.put("accept-language", "en");
        EMResponse response = eduMFA.validateCheckU2F(username, "16786665691788289392", u2fSignResponse, header);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testSuccessWithoutHeader()
    {
        String username = "Test";

        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&transaction_id=16786665691788289392&pass=" +
                                             "&clientdata=eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ" +
                                             "&signaturedata=AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        String u2fSignResponse = "{\"clientData\":\"eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ\"," + "\"errorCode\":0," +
                                 "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                 "\"signatureData\":\"AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg\"}";

        EMResponse response = eduMFA.validateCheckU2F(username, "16786665691788289392", u2fSignResponse);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertTrue(response.status);
        assertTrue(response.value);
    }
}
