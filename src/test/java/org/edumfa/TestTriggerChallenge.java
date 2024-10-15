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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestTriggerChallenge
{
    private ClientAndServer mockServer;
    private EduMFA eduMFA;
    String serviceAccount = "service";
    String servicePass = "pass";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .logger(new EMLogImplementation())
                                 .realm("realm")
                                 .build();
    }

    @Test
    public void testTriggerChallengeSuccess()
    {
        mockServer.when(HttpRequest.request().withPath(EMConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));

        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_TRIGGERCHALLENGE)
                                   .withMethod("POST")
                                   .withBody("user=testuser&realm=realm"))
                  .respond(HttpResponse.response().withBody(Utils.triggerChallengeSuccess()));

        String username = "testuser";
        EMResponse responseTriggerChallenge = eduMFA.triggerChallenges(username);

        assertEquals("otp", responseTriggerChallenge.preferredClientMode);
        assertEquals(1, responseTriggerChallenge.id);
        assertEquals("BittegebenSieeinenOTP-Wertein:", responseTriggerChallenge.message);
        assertEquals("2.0", responseTriggerChallenge.jsonRPCVersion);
        assertEquals("3.6.3", responseTriggerChallenge.emVersion);
        assertEquals("rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b", responseTriggerChallenge.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.triggerChallengeSuccess().replaceAll("[\n\r]", ""), responseTriggerChallenge.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.triggerChallengeSuccess().replaceAll("[\n\r]", ""), responseTriggerChallenge.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(responseTriggerChallenge.status);
        assertFalse(responseTriggerChallenge.value);

        List<Challenge> challenges = responseTriggerChallenge.multichallenge;
        String imageTOTP = "";
        for (Challenge c : challenges)
        {
            if ("totp".equals(c.getType()))
            {
                if (!c.getImage().isEmpty())
                {
                    imageTOTP = c.getImage();
                }
            }
        }
        assertEquals("dataimage", imageTOTP);
    }

    @Test
    public void testNoServiceAccount()
    {
        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .build();

        EMResponse responseTriggerChallenge = eduMFA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testWrongServerURL()
    {
        eduMFA = EduMFA.newBuilder("https://12ds7:1nvcbn080", "test")
                                 .sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .logger(new EMLogImplementation())
                                 .realm("realm")
                                 .build();

        EMResponse responseTriggerChallenge = eduMFA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testNoUsername()
    {
        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .logger(new EMLogImplementation())
                                 .realm("realm")
                                 .build();

        EMResponse responseTriggerChallenge = eduMFA.triggerChallenges("");

        assertNull(responseTriggerChallenge);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
