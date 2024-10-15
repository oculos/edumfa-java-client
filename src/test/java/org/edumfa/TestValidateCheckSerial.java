/*
 * * License:  AGPLv3
 * * This file is part of eduMFA java client. eduMFA java client is a fork of privacyIDEA java client.
 * * Copyright (c) 2024 eduMFA Project-Team
 * * Previous authors of the PrivacyIDEA java client:
 * *
 * * NetKnights GmbH
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
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestValidateCheckSerial
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

    @Test
    public void testNoChallengeResponsePINPlusOTP()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("serial=PISP0001C673&pass=123456"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        String serial = "PISP0001C673";
        String pinPlusOTP = "123456";

        EMResponse response = eduMFA.validateCheckSerial(serial, pinPlusOTP);

        assertEquals(Utils.matchingOneToken(), response.toString());
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertTrue(response.status);
        assertTrue(response.value);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
    }

    @Test
    public void testNoChallengeResponseTransactionID()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(EMConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("serial=PISP0001C673&pass=123456&transaction_id=12093809214"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        String serial = "PISP0001C673";
        String pinPlusOTP = "123456";
        String transactionID = "12093809214";

        EMResponse response = eduMFA.validateCheckSerial(serial, pinPlusOTP, transactionID);

        assertEquals(Utils.matchingOneToken(), response.toString());
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertTrue(response.status);
        assertTrue(response.value);
        assertEquals("3.2.1", response.emVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
