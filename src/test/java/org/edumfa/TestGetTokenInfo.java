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

import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestGetTokenInfo
{
    private ClientAndServer mockServer;
    private EduMFA eduMFA;
    private final String username = "Test";
    private final String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";
    private final String serviceAccount = "admin";
    private final String servicePassword = "admin";
    private final String serviceRealm = "realm";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .serviceAccount(serviceAccount, servicePassword)
                                 .serviceRealm(serviceRealm)
                                 .disableLog()
                                 .httpTimeoutMs(15000)
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();
    }

    @Test
    public void testSuccess()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_AUTH)
                                   .withMethod("POST")
                                   .withBody("username=" + serviceAccount + "&password=" + servicePassword + "&realm=" + serviceRealm))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));

        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withQueryStringParameter("user", username)
                                   .withPath(EMConstants.ENDPOINT_TOKEN)
                                   .withHeader("Authorization", authToken)).respond(HttpResponse.response().withBody(Utils.getTokenResponse()));

        List<TokenInfo> tokenInfoList = eduMFA.getTokenInfo(username);
        assertNotNull(tokenInfoList);
        assertEquals(tokenInfoList.size(), 1);

        TokenInfo tokenInfo = tokenInfoList.get(0);
        assertTrue(tokenInfo.active);
        assertEquals(2, tokenInfo.count);
        assertEquals(10, tokenInfo.countWindow);
        assertEquals("", tokenInfo.description);
        assertEquals(0, tokenInfo.failCount);
        assertEquals(347, tokenInfo.id);
        assertFalse(tokenInfo.locked);
        assertEquals(10, tokenInfo.maxFail);
        assertEquals(6, tokenInfo.otpLen);
        assertEquals("deflocal", tokenInfo.resolver);
        assertFalse(tokenInfo.revoked);
        assertEquals("", tokenInfo.rolloutState);
        assertEquals("OATH00123564", tokenInfo.serial);
        assertEquals(1000, tokenInfo.syncWindow);
        assertEquals("hotp", tokenInfo.tokenType);
        assertFalse(tokenInfo.userEditable);
        assertEquals("5", tokenInfo.userID);
        assertEquals("defrealm", tokenInfo.userRealm);
        assertEquals("Test", tokenInfo.username);

        assertEquals(authToken, eduMFA.getAuthToken());
    }

    @Test
    public void testForNoToken()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withQueryStringParameter("user", "Test")
                                   .withPath(EMConstants.ENDPOINT_TOKEN)
                                   .withHeader("Authorization", authToken))
                  .respond(HttpResponse.response().withBody(Utils.getTokenNoTokenResponse()));

        List<TokenInfo> tokenInfoList = eduMFA.getTokenInfo(username);
        assertNull(tokenInfoList);
    }

    @Test
    public void testNoServiceAccount()
    {
        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false).logger(new EMLogImplementation()).build();

        List<TokenInfo> tokenInfoList = eduMFA.getTokenInfo(username);

        assertNull(tokenInfoList);

        assertNull(eduMFA.getAuthToken());
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
