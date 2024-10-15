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

import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.edumfa.EMConstants.TOKEN_TYPE_PUSH;
import static org.edumfa.EMConstants.TOKEN_TYPE_U2F;
import static org.edumfa.EMConstants.TOKEN_TYPE_WEBAUTHN;

/**
 * This class parses the JSON response of edumfa into a POJO for easier access.
 */
public class EMResponse
{
    public String message = "";
    public String preferredClientMode = "";
    public List<String> messages = new ArrayList<>();
    public List<Challenge> multichallenge = new ArrayList<>();
    public String transactionID = "";
    public String serial = "";
    public String image = "";
    public int id = 0;
    public String jsonRPCVersion = "";
    public boolean status = false;
    public boolean value = false;
    public AuthenticationStatus authentication = AuthenticationStatus.NONE;
    public String emVersion = ""; // e.g. 3.2.1
    public String rawMessage = "";
    public String signature = "";
    public String type = ""; // Type of token that was matching the request
    public int otpLength = 0;

    public EMError error = null;

    public boolean pushAvailable()
    {
        return multichallenge.stream().anyMatch(c -> TOKEN_TYPE_PUSH.equals(c.getType()));
    }

    /**
     * Get the messages of all triggered push challenges reduced to a string to show on the push UI.
     *
     * @return messages of all push challenges combined
     */
    public String pushMessage()
    {
        return reduceChallengeMessagesWhere(c -> TOKEN_TYPE_PUSH.equals(c.getType()));
    }

    /**
     * Get the messages of all token that require an input field (HOTP, TOTP, SMS, Email...) reduced to a single string
     * to show with the input field.
     *
     * @return message string
     */
    public String otpMessage()
    {
        // Any challenge that is not WebAuthn, U2F or Push is considered OTP
        return reduceChallengeMessagesWhere(c -> !(TOKEN_TYPE_PUSH.equals(c.getType())));
    }

    private String reduceChallengeMessagesWhere(Predicate<Challenge> predicate)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(multichallenge.stream().filter(predicate).map(Challenge::getMessage).distinct().reduce("", (a, s) -> a + s + ", ").trim());

        if (sb.length() > 0)
        {
            sb.deleteCharAt(sb.length() - 1);
        }

        return sb.toString();
    }

    /**
     * @return list of token types that were triggered or an empty list
     */
    public List<String> triggeredTokenTypes()
    {
        return multichallenge.stream().map(Challenge::getType).distinct().collect(Collectors.toList());
    }

    /**
     * Get all WebAuthn challenges from the multi_challenge.
     *
     * @return List of WebAuthn objects or empty list
     */
    public List<WebAuthn> webAuthnSignRequests()
    {
        List<WebAuthn> ret = new ArrayList<>();
        multichallenge.stream().filter(c -> TOKEN_TYPE_WEBAUTHN.equals(c.getType())).collect(Collectors.toList()).forEach(c ->
                                                                                                                          {
                                                                                                                              if (c instanceof WebAuthn)
                                                                                                                              {
                                                                                                                                  ret.add((WebAuthn) c);
                                                                                                                              }
                                                                                                                          });
        return ret;
    }

    /**
     * Return the SignRequest that contains the merged allowCredentials so that the SignRequest can be used with any device that
     * is allowed to answer the SignRequest.
     * <p>
     * Can return an empty string if an error occurred or if no WebAuthn challenges have been triggered.
     *
     * @return merged SignRequest or empty string.
     */
    public String mergedSignRequest()
    {
        List<WebAuthn> webAuthnSignRequests = webAuthnSignRequests();
        if (webAuthnSignRequests.isEmpty())
        {
            return "";
        }
        if (webAuthnSignRequests.size() == 1)
        {
            return webAuthnSignRequests.get(0).signRequest();
        }

        WebAuthn webAuthn = webAuthnSignRequests.get(0);
        List<String> stringSignRequests = webAuthnSignRequests.stream().map(WebAuthn::signRequest).collect(Collectors.toList());

        try
        {
            return JSONParser.mergeWebAuthnSignRequest(webAuthn, stringSignRequests);
        }
        catch (JsonSyntaxException e)
        {
            return "";
        }
    }

    /**
     * Get all U2F challenges from the multi_challenge.
     *
     * @return List of U2F objects or empty list
     */
    public List<U2F> u2fSignRequests()
    {
        List<U2F> ret = new ArrayList<>();
        multichallenge.stream().filter(c -> TOKEN_TYPE_U2F.equals(c.getType())).collect(Collectors.toList()).forEach(c ->
                                                                                                                     {
                                                                                                                         if (c instanceof U2F)
                                                                                                                         {
                                                                                                                             ret.add((U2F) c);
                                                                                                                         }
                                                                                                                     });
        return ret;
    }

    @Override
    public String toString()
    {
        return rawMessage;
    }
}
