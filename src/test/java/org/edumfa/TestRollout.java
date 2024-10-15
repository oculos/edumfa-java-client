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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestRollout
{
    private EduMFA eduMFA;
    private ClientAndServer mockServer;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .serviceAccount("admin", "admin")
                                 .logger(new EMLogImplementation())
                                 .build();
    }

    @Test
    public void testSuccess()
    {
        String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";

        String img = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";

        mockServer.when(HttpRequest.request().withPath(EMConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));


        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_TOKEN_INIT)
                                   .withMethod("POST")
                                   .withHeader(Header.header("Authorization", authToken)))
                  .respond(HttpResponse.response()
                                       .withBody(Utils.rolloutSuccess()));

        RolloutInfo rolloutInfo = eduMFA.tokenRollout("games", "hotp");

        assertEquals(img, rolloutInfo.googleurl.img);
        assertNotNull(rolloutInfo.googleurl.description);
        assertNotNull(rolloutInfo.googleurl.value);

        assertNotNull(rolloutInfo.otpkey.description);
        assertNotNull(rolloutInfo.otpkey.value);
        assertNotNull(rolloutInfo.otpkey.img);
        assertNotNull(rolloutInfo.otpkey.value_b32);

        assertNotNull(rolloutInfo.oathurl.value);
        assertNotNull(rolloutInfo.oathurl.description);
        assertNotNull(rolloutInfo.oathurl.img);

        assertNotNull(rolloutInfo.serial);
        assertTrue(rolloutInfo.rolloutState.isEmpty());
    }

    @Test
    public void testNoServiceAccount()
    {
        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();

        RolloutInfo rolloutInfo = eduMFA.tokenRollout("games", "hotp");

        assertNull(rolloutInfo);
    }

    @Test
    public void testRolloutViaValidateCheck()
    {
        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();

        String image = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";
        String username = "testuser";

        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=" + username + "&pass="))
                  .respond(HttpResponse.response().withBody(Utils.rolloutViaChallenge()));

        EMResponse responseValidateCheck = eduMFA.validateCheck(username, "");

        assertEquals(image, responseValidateCheck.image);
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
