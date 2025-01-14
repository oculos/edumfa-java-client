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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.edumfa.EMConstants.ASSERTIONCLIENTEXTENSIONS;
import static org.edumfa.EMConstants.ATTRIBUTES;
import static org.edumfa.EMConstants.AUTHENTICATION;
import static org.edumfa.EMConstants.AUTHENTICATORDATA;
import static org.edumfa.EMConstants.CLIENTDATA;
import static org.edumfa.EMConstants.CLIENT_MODE;
import static org.edumfa.EMConstants.CODE;
import static org.edumfa.EMConstants.CREDENTIALID;
import static org.edumfa.EMConstants.DETAIL;
import static org.edumfa.EMConstants.ERROR;
import static org.edumfa.EMConstants.ID;
import static org.edumfa.EMConstants.IMAGE;
import static org.edumfa.EMConstants.INFO;
import static org.edumfa.EMConstants.JSONRPC;
import static org.edumfa.EMConstants.MAXFAIL;
import static org.edumfa.EMConstants.MESSAGE;
import static org.edumfa.EMConstants.MESSAGES;
import static org.edumfa.EMConstants.MULTI_CHALLENGE;
import static org.edumfa.EMConstants.OTPLEN;
import static org.edumfa.EMConstants.PREFERRED_CLIENT_MODE;
import static org.edumfa.EMConstants.REALMS;
import static org.edumfa.EMConstants.RESULT;
import static org.edumfa.EMConstants.SERIAL;
import static org.edumfa.EMConstants.SIGNATURE;
import static org.edumfa.EMConstants.SIGNATUREDATA;
import static org.edumfa.EMConstants.STATUS;
import static org.edumfa.EMConstants.TOKEN;
import static org.edumfa.EMConstants.TOKENS;
import static org.edumfa.EMConstants.TOKEN_TYPE_U2F;
import static org.edumfa.EMConstants.TOKEN_TYPE_WEBAUTHN;
import static org.edumfa.EMConstants.TRANSACTION_ID;
import static org.edumfa.EMConstants.TYPE;
import static org.edumfa.EMConstants.U2F_SIGN_REQUEST;
import static org.edumfa.EMConstants.USERHANDLE;
import static org.edumfa.EMConstants.USERNAME;
import static org.edumfa.EMConstants.VALUE;
import static org.edumfa.EMConstants.VERSION_NUMBER;
import static org.edumfa.EMConstants.WEBAUTHN_SIGN_REQUEST;

public class JSONParser
{
    private final EduMFA edumfa;

    public JSONParser(EduMFA edumfa)
    {
        this.edumfa = edumfa;
    }

    /**
     * Format a json string with indentation.
     *
     * @param json json string
     * @return formatted json string
     */
    public String formatJson(String json)
    {
        if (json == null || json.isEmpty())
        {
            return "";
        }

        JsonObject obj;
        Gson gson = new GsonBuilder().setPrettyPrinting().setLenient().create();
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error(e.getMessage());
            return json;
        }

        return gson.toJson(obj);
    }

    /**
     * Extract the auth token from the response of the server.
     *
     * @param serverResponse response of the server
     * @return the auth token or null if error
     */
    String extractAuthToken(String serverResponse)
    {
        if (serverResponse != null && !serverResponse.isEmpty())
        {
            JsonElement root = JsonParser.parseString(serverResponse);
            if (root != null)
            {
                try
                {
                    JsonObject obj = root.getAsJsonObject();
                    return obj.getAsJsonObject(RESULT).getAsJsonObject(VALUE).getAsJsonPrimitive(TOKEN).getAsString();
                }
                catch (Exception e)
                {
                    edumfa.error("Response did not contain an authorization token: " + formatJson(serverResponse));
                }
            }
        }
        else
        {
            edumfa.error("/auth response was empty or null!");
        }
        return null;
    }

    /**
     * Parse the response of the server into a EMResponse object.
     *
     * @param serverResponse response of the server
     * @return EMResponse or null if input is empty
     */
    public EMResponse parseEMResponse(String serverResponse)
    {
        if (serverResponse == null || serverResponse.isEmpty())
        {
            return null;
        }

        EMResponse response = new EMResponse();
        response.rawMessage = serverResponse;

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error(e);
            return response;
        }

        response.id = getInt(obj, ID);
        response.emVersion = getString(obj, VERSION_NUMBER);
        response.signature = getString(obj, SIGNATURE);
        response.jsonRPCVersion = getString(obj, JSONRPC);

        JsonObject result = obj.getAsJsonObject(RESULT);
        if (result != null)
        {
            String r = getString(result, AUTHENTICATION);
            for (AuthenticationStatus en : AuthenticationStatus.values())
            {
                if (en.toString().equals(r))
                {
                    response.authentication = en;
                }
            }
            response.status = getBoolean(result, STATUS);
            response.value = getBoolean(result, VALUE);

            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull())
            {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                response.error = new EMError(getInt(errObj, CODE), getString(errObj, MESSAGE));
                return response;
            }
        }

        JsonElement detailElem = obj.get(DETAIL);
        if (detailElem != null && !detailElem.isJsonNull())
        {
            JsonObject detail = obj.getAsJsonObject(DETAIL);

            // Translate some preferred client mode names
            String modeFromResponse = getString(detail, PREFERRED_CLIENT_MODE);
            if ("poll".equals(modeFromResponse))
            {
                response.preferredClientMode = "push";
            }
            else if ("interactive".equals(modeFromResponse))
            {
                response.preferredClientMode = "otp";
            }
            else
            {
                response.preferredClientMode = modeFromResponse;
            }
            response.message = getString(detail, MESSAGE);
            response.image = getString(detail, IMAGE);
            response.serial = getString(detail, SERIAL);
            response.transactionID = getString(detail, TRANSACTION_ID);
            response.type = getString(detail, TYPE);
            response.otpLength = getInt(detail, OTPLEN);

            JsonArray arrMessages = detail.getAsJsonArray(MESSAGES);
            if (arrMessages != null)
            {
                arrMessages.forEach(val ->
                                    {
                                        if (val != null)
                                        {
                                            response.messages.add(val.getAsString());
                                        }
                                    });
            }

            JsonArray arrChallenges = detail.getAsJsonArray(MULTI_CHALLENGE);
            if (arrChallenges != null)
            {
                for (int i = 0; i < arrChallenges.size(); i++)
                {
                    JsonObject challenge = arrChallenges.get(i).getAsJsonObject();
                    String serial = getString(challenge, SERIAL);
                    String message = getString(challenge, MESSAGE);
                    String clientmode = getString(challenge, CLIENT_MODE);
                    String image = getString(challenge, IMAGE);
                    String transactionid = getString(challenge, TRANSACTION_ID);
                    String type = getString(challenge, TYPE);

                    if (TOKEN_TYPE_WEBAUTHN.equals(type))
                    {
                        String webAuthnSignRequest = getItemFromAttributes(WEBAUTHN_SIGN_REQUEST, challenge);
                        response.multichallenge.add(new WebAuthn(serial, message, clientmode, image, transactionid, webAuthnSignRequest));
                    }
                    else if (TOKEN_TYPE_U2F.equals(type))
                    {
                        String u2fSignRequest = getItemFromAttributes(U2F_SIGN_REQUEST, challenge);
                        response.multichallenge.add(new U2F(serial, message, clientmode, image, transactionid, u2fSignRequest));
                    }
                    else
                    {
                        response.multichallenge.add(new Challenge(serial, message, clientmode, image, transactionid, type));
                    }
                }
            }
        }
        return response;
    }

    static String mergeWebAuthnSignRequest(WebAuthn webAuthn, List<String> arr) throws JsonSyntaxException
    {
        List<JsonArray> extracted = new ArrayList<>();
        for (String signRequest : arr)
        {
            JsonObject obj = JsonParser.parseString(signRequest).getAsJsonObject();
            extracted.add(obj.getAsJsonArray("allowCredentials"));
        }

        JsonObject signRequest = JsonParser.parseString(webAuthn.signRequest()).getAsJsonObject();
        JsonArray allowCredentials = new JsonArray();
        extracted.forEach(allowCredentials::addAll);

        signRequest.add("allowCredentials", allowCredentials);

        return signRequest.toString();
    }

    private String getItemFromAttributes(String item, JsonObject jsonObject)
    {
        String ret = "";
        JsonElement attributeElement = jsonObject.get(ATTRIBUTES);
        if (attributeElement != null && !attributeElement.isJsonNull())
        {
            JsonElement requestElement = attributeElement.getAsJsonObject().get(item);
            if (requestElement != null && !requestElement.isJsonNull())
            {
                ret = requestElement.toString();
            }
        }
        return ret;
    }

    /**
     * Parse the response of the /token endpoint into a list of objects.
     *
     * @param serverResponse response of the server.
     * @return list of token info objects or null
     */
    List<TokenInfo> parseTokenInfoList(String serverResponse)
    {
        if (serverResponse == null || serverResponse.isEmpty())
        {
            return null;
        }

        List<TokenInfo> ret = new ArrayList<>();
        JsonObject object;
        try
        {
            object = JsonParser.parseString(serverResponse).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error(e);
            return ret;
        }

        JsonObject result = object.getAsJsonObject(RESULT);
        if (result != null)
        {
            JsonObject value = result.getAsJsonObject(VALUE);

            if (value != null)
            {
                JsonArray tokens = value.getAsJsonArray(TOKENS);
                if (tokens != null)
                {
                    List<TokenInfo> infos = new ArrayList<>();
                    tokens.forEach(jsonValue -> infos.add(parseSingleTokenInfo(jsonValue.toString())));
                    ret = infos;
                }
            }
        }
        return ret;
    }

    /**
     * Parse the info of a single token into an object.
     *
     * @param json json array element as string
     * @return TokenInfo object, might be null object is json is empty
     */
    private TokenInfo parseSingleTokenInfo(String json)
    {
        TokenInfo info = new TokenInfo();
        if (json == null || json.isEmpty())
        {
            return info;
        }

        info.rawJson = json;

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error(e);
            return info;
        }

        info.active = getBoolean(obj, "active");
        info.count = getInt(obj, "count");
        info.countWindow = getInt(obj, "count_window");
        info.description = getString(obj, "description");
        info.failCount = getInt(obj, "failcount");
        info.id = getInt(obj, ID);
        info.locked = getBoolean(obj, "locked");
        info.maxFail = getInt(obj, MAXFAIL);
        info.otpLen = getInt(obj, OTPLEN);
        info.resolver = getString(obj, "resolver");
        info.revoked = getBoolean(obj, "revoked");
        info.rolloutState = getString(obj, "rollout_state");
        info.serial = getString(obj, SERIAL);
        info.image = getString(obj, IMAGE);
        info.syncWindow = getInt(obj, "sync_window");
        info.tokenType = getString(obj, "tokentype");
        info.userEditable = getBoolean(obj, "user_editable");
        info.userID = getString(obj, "user_id");
        info.userRealm = getString(obj, "user_realm");
        info.username = getString(obj, USERNAME);

        JsonObject joInfo = obj.getAsJsonObject(INFO);
        if (joInfo != null)
        {
            joInfo.entrySet().forEach(entry ->
                                      {
                                          if (entry.getKey() != null && entry.getValue() != null)
                                          {
                                              info.info.put(entry.getKey(), entry.getValue().getAsString());
                                          }
                                      });
        }

        JsonArray arrRealms = obj.getAsJsonArray(REALMS);
        if (arrRealms != null)
        {
            arrRealms.forEach(val ->
                              {
                                  if (val != null)
                                  {
                                      info.realms.add(val.getAsString());
                                  }
                              });
        }
        return info;
    }

    /**
     * Parse the response of /token/init into an object.
     *
     * @param serverResponse response of /token/init
     * @return RolloutInfo object, might be null object if response is empty
     */
    RolloutInfo parseRolloutInfo(String serverResponse)
    {
        RolloutInfo rinfo = new RolloutInfo();
        rinfo.raw = serverResponse;
        rinfo.googleurl = new RolloutInfo.GoogleURL();
        rinfo.oathurl = new RolloutInfo.OATHURL();
        rinfo.otpkey = new RolloutInfo.OTPKey();

        if (serverResponse == null || serverResponse.isEmpty())
        {
            return rinfo;
        }

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();

            JsonObject result = obj.getAsJsonObject(RESULT);
            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull())
            {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                rinfo.error = new EMError(getInt(errObj, CODE), getString(errObj, MESSAGE));
                return rinfo;
            }

            JsonObject detail = obj.getAsJsonObject("detail");
            if (detail != null)
            {
                JsonObject google = detail.getAsJsonObject("googleurl");
                if (google != null)
                {
                    rinfo.googleurl.description = getString(google, "description");
                    rinfo.googleurl.img = getString(google, "img");
                    rinfo.googleurl.value = getString(google, "value");
                }

                JsonObject oath = detail.getAsJsonObject("oath");
                if (oath != null)
                {
                    rinfo.oathurl.description = getString(oath, "description");
                    rinfo.oathurl.img = getString(oath, "img");
                    rinfo.oathurl.value = getString(oath, "value");
                }

                JsonObject otp = detail.getAsJsonObject("otpkey");
                if (otp != null)
                {
                    rinfo.otpkey.description = getString(otp, "description");
                    rinfo.otpkey.img = getString(otp, "img");
                    rinfo.otpkey.value = getString(otp, "value");
                    rinfo.otpkey.value_b32 = getString(otp, "value_b32");
                }

                rinfo.serial = getString(detail, "serial");
                rinfo.rolloutState = getString(detail, "rollout_state");
            }
        }
        catch (JsonSyntaxException | ClassCastException e)
        {
            edumfa.error(e);
            return rinfo;
        }

        return rinfo;
    }

    /**
     * Parse the json string that is returned from the browser after signing the WebAuthnSignRequest into a map.
     * The map contains the parameters with the corresponding keys ready to be sent to the server.
     *
     * @param json json string from the browser
     * @return map
     */
    Map<String, String> parseWebAuthnSignResponse(String json)
    {
        Map<String, String> params = new LinkedHashMap<>();
        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error("WebAuthn sign response has the wrong format: " + e.getLocalizedMessage());
            return null;
        }

        params.put(CREDENTIALID, getString(obj, CREDENTIALID));
        params.put(CLIENTDATA, getString(obj, CLIENTDATA));
        params.put(SIGNATUREDATA, getString(obj, SIGNATUREDATA));
        params.put(AUTHENTICATORDATA, getString(obj, AUTHENTICATORDATA));

        // The userhandle and assertionclientextension fields are optional
        String userhandle = getString(obj, USERHANDLE);
        if (!userhandle.isEmpty())
        {
            params.put(USERHANDLE, userhandle);
        }
        String extensions = getString(obj, ASSERTIONCLIENTEXTENSIONS);
        if (!extensions.isEmpty())
        {
            params.put(ASSERTIONCLIENTEXTENSIONS, extensions);
        }
        return params;
    }

    /**
     * Parse the json string that is returned from the browser after signing the U2FSignRequest into a map.
     * The map contains the parameters with the corresponding keys ready to be sent to the server.
     *
     * @param json json string from the browser
     * @return map
     */
    Map<String, String> parseU2FSignResponse(String json)
    {
        Map<String, String> params = new LinkedHashMap<>();
        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            edumfa.error("U2F sign response has the wrong format: " + e.getLocalizedMessage());
            return null;
        }

        params.put(CLIENTDATA, getString(obj, "clientData"));
        params.put(SIGNATUREDATA, getString(obj, "signatureData"));

        return params;
    }

    private boolean getBoolean(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isBoolean() && primitive.getAsBoolean();
    }

    private int getInt(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isNumber() ? primitive.getAsInt() : 0;
    }

    private String getString(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isString() ? primitive.getAsString() : "";
    }

    private JsonPrimitive getPrimitiveOrNull(JsonObject obj, String name)
    {
        JsonPrimitive primitive = null;
        try
        {
            primitive = obj.getAsJsonPrimitive(name);
        }
        catch (Exception e)
        {
            // Just catch the exception instead of checking to get some log
            edumfa.error("Cannot get " + name + " from JSON");
            edumfa.error(e);
        }
        return primitive;
    }
}
