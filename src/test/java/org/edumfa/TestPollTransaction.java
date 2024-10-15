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
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TestPollTransaction
{
    private ClientAndServer mockServer;
    private EduMFA eduMFA;
    private final String username = "testuser";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        eduMFA = EduMFA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new EMLogImplementation())
                                 .simpleLogger(System.out::println)
                                 .build();
    }

    @Test
    public void testPushSynchronous() throws InterruptedException
    {
        // Set the initial "challenges triggered" response, pass is empty here
        // How the challenge is triggered depends on the configuration of the privacyIDEA server
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass="))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.pollGetChallenges())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        EMResponse initialResponse = eduMFA.validateCheck(username, null);

        // Check the triggered challenges - the other things are already tested in org.privacyidea.TestOTP
        List<Challenge> challenges = initialResponse.multichallenge;

        Challenge hotpChallenge = challenges.stream()
                                            .filter(c -> c.getSerial().equals("OATH00020121"))
                                            .findFirst()
                                            .orElse(null);
        assertNotNull(hotpChallenge);
        assertEquals("Bitte geben Sie einen OTP-Wert ein: ", hotpChallenge.getMessage());
        assertEquals("02659936574063359702", hotpChallenge.getTransactionID());
        assertEquals("hotp", hotpChallenge.getType());
        assertEquals("", hotpChallenge.getImage());
        assertTrue(hotpChallenge.getAttributes().isEmpty());

        assertEquals("push", initialResponse.preferredClientMode);

        Challenge pushChallenge = challenges.stream()
                                            .filter(c -> c.getSerial().equals("PIPU0001F75E"))
                                            .findFirst()
                                            .orElse(null);
        assertNotNull(pushChallenge);
        assertEquals("Please confirm the authentication on your mobile device!", pushChallenge.getMessage());
        assertEquals("02659936574063359702", pushChallenge.getTransactionID());
        assertEquals("push", pushChallenge.getType());
        assertTrue(pushChallenge.getAttributes().isEmpty());

        String imagePush = "";
        for (Challenge c : challenges)
        {
            if ("push".equals(c.getType()))
            {
                if (!c.getImage().isEmpty())
                {
                    imagePush = c.getImage();
                }
            }
        }
        assertEquals("dataimage", imagePush);

        List<String> triggeredTypes = initialResponse.triggeredTokenTypes();
        assertTrue(triggeredTypes.contains("push"));
        assertTrue(triggeredTypes.contains("hotp"));

        assertEquals(2, initialResponse.messages.size());

        // Set the server up to respond to the polling requests twice with false
        setPollTransactionResponse(false, 2);

        // Polling is controlled by the code using the sdk
        for (int i = 0; i < 2; i++)
        {
            assertFalse(eduMFA.pollTransaction(initialResponse.transactionID));
            Thread.sleep(500);
        }

        // Set the server to respond with true
        setPollTransactionResponse(true, 1);
        assertTrue(eduMFA.pollTransaction(initialResponse.transactionID));

        // Now the transaction has to be finalized manually
        setFinalizationResponse(initialResponse.transactionID);

        EMResponse response = eduMFA.validateCheck(username, null, initialResponse.transactionID);
        assertTrue(response.value);

        //push side functions
        boolean pushAvailable = response.pushAvailable();
        assertFalse(pushAvailable);
        String pushMessage = response.pushMessage();
        assertEquals("", pushMessage);
    }

    private void setFinalizationResponse(String transactionID)
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=&transaction_id=" + transactionID))
                  .respond(HttpResponse.response()
                                       .withBody(Utils.foundMatchingChallenge()));
    }

    private void setPollTransactionResponse(boolean value, int times)
    {
        String val = value ? "true" : "false";
        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withPath("/validate/polltransaction")
                                   .withQueryStringParameter("transaction_id", "02659936574063359702"), Times.exactly(times))
                  .respond(HttpResponse.response()
                                       .withBody("{\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
                                                 "    \"result\": {\n" + "        \"status\": true,\n" +
                                                 "        \"value\": " + val + "\n" + "    },\n" +
                                                 "    \"time\": 1589446811.1909237,\n" +
                                                 "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                                 "    \"versionnumber\": \"3.2.1\",\n" +
                                                 "    \"signature\": \"rsa_sha256_pss:\"\n" + "}")
                                       .withDelay(TimeUnit.MILLISECONDS, 50));
    }


    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
