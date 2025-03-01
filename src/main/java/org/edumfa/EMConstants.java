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

import java.util.Arrays;
import java.util.List;

public class EMConstants
{
    private EMConstants()
    {
    }

    public static final String GET = "GET";
    public static final String POST = "POST";

    // ENDPOINTS
    public static final String ENDPOINT_AUTH = "/auth";
    public static final String ENDPOINT_TOKEN_INIT = "/token/init";
    public static final String ENDPOINT_TRIGGERCHALLENGE = "/validate/triggerchallenge";
    public static final String ENDPOINT_POLLTRANSACTION = "/validate/polltransaction";
    public static final String ENDPOINT_VALIDATE_CHECK = "/validate/check";
    public static final String ENDPOINT_TOKEN = "/token/";

    public static final String HEADER_ORIGIN = "Origin";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_USER_AGENT = "User-Agent";

    // TOKEN TYPES
    public static final String TOKEN_TYPE_PUSH = "push";
    public static final String TOKEN_TYPE_OTP = "otp";
    public static final String TOKEN_TYPE_TOTP = "totp";
    public static final String TOKEN_TYPE_HOTP = "hotp";
    public static final String TOKEN_TYPE_WEBAUTHN = "webauthn";
    public static final String TOKEN_TYPE_U2F = "u2f";

    // JSON KEYS
    public static final String USERNAME = "username";
    public static final String USER = "user";
    public static final String PASSWORD = "password";
    public static final String PASS = "pass";
    public static final String SERIAL = "serial";
    public static final String TYPE = "type";
    public static final String TRANSACTION_ID = "transaction_id";
    public static final String REALM = "realm";
    public static final String REALMS = "realms";
    public static final String GENKEY = "genkey";
    public static final String OTPKEY = "otpkey";
    public static final String RESULT = "result";
    public static final String VALUE = "value";
    public static final String TOKENS = "tokens";
    public static final String TOKEN = "token";
    public static final String PREFERRED_CLIENT_MODE = "preferred_client_mode";
    public static final String MESSAGE = "message";
    public static final String CLIENT_MODE = "client_mode";
    public static final String IMAGE = "image";
    public static final String MESSAGES = "messages";
    public static final String MULTI_CHALLENGE = "multi_challenge";
    public static final String ATTRIBUTES = "attributes";
    public static final String DETAIL = "detail";
    public static final String OTPLEN = "otplen";
    public static final String CODE = "code";
    public static final String ERROR = "error";
    public static final String STATUS = "status";
    public static final String JSONRPC = "jsonrpc";
    public static final String SIGNATURE = "signature";
    public static final String VERSION_NUMBER = "versionnumber";
    public static final String AUTHENTICATION = "authentication";
    public static final String ID = "id";
    public static final String MAXFAIL = "maxfail";
    public static final String INFO = "info";
    public static final String LOCKED = "locked";
    public static final String FAILCOUNT = "failcount";
    public static final String DESCRIPTION = "description";
    public static final String COUNT = "count";
    public static final String COUNT_WINDOW = "count_window";
    public static final String ACTIVE = "active";
    public static final String RESOLVER = "resolver";
    public static final String REVOKED = "revoked";
    public static final String SYNC_WINDOW = "sync_window";

    // WebAuthn and U2F params
    public static final String WEBAUTHN_SIGN_REQUEST = "webAuthnSignRequest";
    public static final String CREDENTIALID = "credentialid";
    public static final String CLIENTDATA = "clientdata";
    public static final String SIGNATUREDATA = "signaturedata";
    public static final String AUTHENTICATORDATA = "authenticatordata";
    public static final String USERHANDLE = "userhandle";
    public static final String ASSERTIONCLIENTEXTENSIONS = "assertionclientextensions";
    public static final String U2F_SIGN_REQUEST = "u2fSignRequest";


    // These will be excluded from url encoding
    public static final List<String> WEBAUTHN_PARAMETERS = Arrays.asList(CREDENTIALID, CLIENTDATA, SIGNATUREDATA, AUTHENTICATORDATA, USERHANDLE,
                                                                         ASSERTIONCLIENTEXTENSIONS);
    public static final List<String> U2F_PARAMETERS = Arrays.asList(CLIENTDATA, SIGNATUREDATA);

}
