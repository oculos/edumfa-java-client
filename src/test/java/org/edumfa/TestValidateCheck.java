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
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestValidateCheck
{
    private ClientAndServer mockServer;
    private EduMFA eduMFA;
    private final String username = "testuser";
    private final String otp = "123456";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();
    }

    @Test
    public void testOTPSuccess()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        EMResponse response = eduMFA.validateCheck(username, otp);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testOTPAddHeader()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        Map<String, String> header = new HashMap<>();
        header.put("accept-language", "en");
        EMResponse response = eduMFA.validateCheck(username, otp, header);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testLostValues()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.lostValues())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        EMResponse response = eduMFA.validateCheck(username, otp);

        assertEquals("", response.emVersion);
        assertEquals("", response.message);
        assertEquals(0, response.otpLength);
        assertEquals(0, response.id);
        assertEquals("", response.jsonRPCVersion);
        assertEquals("", response.serial);
        assertEquals("", response.type);
        assertEquals("", response.signature);
    }

    @Test
    public void testEmptyResponse()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody("")
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        EMResponse response = eduMFA.validateCheck(username, otp);

        // An empty response returns null
        assertNull(response);
    }

    @Test
    public void testNoResponse()
    {
        // No server setup - server might be offline/unreachable etc
        EMResponse response = eduMFA.validateCheck(username, otp);

        // No response also returns null - the exception is forwarded to the ILoggerBridge if set
        assertNull(response);
    }

    @Test
    public void testUserNotFound()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=TOTP0001AFB9&pass=12"))
                  .respond(HttpResponse.response().withStatusCode(400).withBody(Utils.errorUserNotFound()));

        String user = "TOTP0001AFB9";
        String pin = "12";

        EMResponse response = eduMFA.validateCheck(user, pin);

        assertEquals(Utils.errorUserNotFound(), response.toString());
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertFalse(response.status);
        assertNotNull(response.error);
        assertEquals("rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0", response.signature);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
