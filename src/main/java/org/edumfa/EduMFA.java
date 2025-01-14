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

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.edumfa.EMConstants.ENDPOINT_AUTH;
import static org.edumfa.EMConstants.ENDPOINT_POLLTRANSACTION;
import static org.edumfa.EMConstants.ENDPOINT_TOKEN;
import static org.edumfa.EMConstants.ENDPOINT_TOKEN_INIT;
import static org.edumfa.EMConstants.ENDPOINT_TRIGGERCHALLENGE;
import static org.edumfa.EMConstants.ENDPOINT_VALIDATE_CHECK;
import static org.edumfa.EMConstants.GENKEY;
import static org.edumfa.EMConstants.GET;
import static org.edumfa.EMConstants.HEADER_ORIGIN;
import static org.edumfa.EMConstants.OTPKEY;
import static org.edumfa.EMConstants.PASS;
import static org.edumfa.EMConstants.PASSWORD;
import static org.edumfa.EMConstants.POST;
import static org.edumfa.EMConstants.REALM;
import static org.edumfa.EMConstants.SERIAL;
import static org.edumfa.EMConstants.TRANSACTION_ID;
import static org.edumfa.EMConstants.TYPE;
import static org.edumfa.EMConstants.USER;
import static org.edumfa.EMConstants.USERNAME;

/**
 * This is the main class. It implements the common endpoints such as /validate/check as methods for easy usage.
 * To create an instance of this class, use the nested edumfa.Builder class.
 */
public class EduMFA implements Closeable
{
    private final EMConfig configuration;
    private final IPILogger log;
    private final IPISimpleLogger simpleLog;
    private final Endpoint endpoint;
    // Thread pool for connections
    private final BlockingQueue<Runnable> queue = new ArrayBlockingQueue<>(1000);
    private final ThreadPoolExecutor threadPool = new ThreadPoolExecutor(20, 20, 10, TimeUnit.SECONDS, queue);
    final JSONParser parser;
    // Responses from these endpoints will not be logged. The list can be overwritten.
    private List<String> logExcludedEndpoints = Arrays.asList(EMConstants.ENDPOINT_AUTH,
                                                              EMConstants.ENDPOINT_POLLTRANSACTION); //Collections.emptyList(); //

    private EduMFA(EMConfig configuration, IPILogger logger, IPISimpleLogger simpleLog)
    {
        this.log = logger;
        this.simpleLog = simpleLog;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this);
        this.parser = new JSONParser(this);
        this.threadPool.allowCoreThreadTimeOut(true);
    }

    /**
     * @see edumfa#validateCheck(String, String, String, Map)
     */
    public EMResponse validateCheck(String username, String pass)
    {
        return this.validateCheck(username, pass, null, Collections.emptyMap());
    }

    /**
     * @see edumfa#validateCheck(String, String, String, Map)
     */
    public EMResponse validateCheck(String username, String pass, Map<String, String> headers)
    {
        return this.validateCheck(username, pass, null, headers);
    }

    /**
     * @see edumfa#validateCheck(String, String, String, Map)
     */
    public EMResponse validateCheck(String username, String pass, String transactionId)
    {
        return this.validateCheck(username, pass, transactionId, Collections.emptyMap());
    }

    /**
     * Send a request to validate/check with the given parameters.
     * Which parameters to send depends on the use case and how edumfa is configured.
     * (E.g. this can also be used to trigger challenges without a service account)
     *
     * @param username      username
     * @param pass          pass/otp value
     * @param transactionId optional, will be appended if set
     * @param headers       optional headers for the request
     * @return EMResponse object containing the response or null if error
     */
    public EMResponse validateCheck(String username, String pass, String transactionId, Map<String, String> headers)
    {
        return getEMResponse(USER, username, pass, headers, transactionId);
    }

    /**
     * @see edumfa#validateCheckSerial(String, String, String, Map)
     */
    public EMResponse validateCheckSerial(String serial, String pass)
    {
        return this.validateCheckSerial(serial, pass, null, Collections.emptyMap());
    }

    /**
     * @see edumfa#validateCheckSerial(String, String, String, Map)
     */
    public EMResponse validateCheckSerial(String serial, String pass, Map<String, String> headers)
    {
        return this.validateCheckSerial(serial, pass, null, headers);
    }

    /**
     * @see edumfa#validateCheckSerial(String, String, String, Map)
     */
    public EMResponse validateCheckSerial(String serial, String pass, String transactionId)
    {
        return this.validateCheckSerial(serial, pass, transactionId, Collections.emptyMap());
    }

    /**
     * Send a request to /validate/check with the serial rather than the username to identify exact token.
     *
     * @param serial        serial of the token
     * @param pass          pass/otp value
     * @param transactionId transactionId
     * @return EMResponse or null if error
     */
    public EMResponse validateCheckSerial(String serial, String pass, String transactionId, Map<String, String> headers)
    {
        return getEMResponse(SERIAL, serial, pass, headers, transactionId);
    }

    /**
     * Used by validateCheck and validateCheckSerial to get the PI Response.
     *
     * @param type          distinguish between user and serial to set forwarded input to the right PI-request param
     * @param input         forwarded username for classic validateCheck or serial to trigger exact token
     * @param pass          OTP, PIN+OTP or password to use
     * @param headers       optional headers for the request
     * @param transactionId optional, will be appended if set
     * @return EMResponse object containing the response or null if error
     */
    private EMResponse getEMResponse(String type, String input, String pass, Map<String, String> headers, String transactionId)
    {
        Map<String, String> params = new LinkedHashMap<>();
        // Add forwarded user or serial to the params
        params.put(type, input);
        params.put(PASS, (pass != null ? pass : ""));
        appendRealm(params);
        if (transactionId != null && !transactionId.isEmpty())
        {
            params.put(TRANSACTION_ID, transactionId);
        }
        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, headers, false, POST);
        return this.parser.parseEMResponse(response);
    }

    /**
     * @see edumfa#validateCheckWebAuthn(String, String, String, String, Map)
     */
    public EMResponse validateCheckWebAuthn(String user, String transactionId, String signResponse, String origin)
    {
        return this.validateCheckWebAuthn(user, transactionId, signResponse, origin, Collections.emptyMap());
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a WebAuthn token.
     *
     * @param user                 username
     * @param transactionId        transactionId
     * @param webAuthnSignResponse the WebAuthnSignResponse as returned from the browser
     * @param origin               server name that was used for
     * @param headers              optional headers for the request
     * @return EMResponse or null if error
     */
    public EMResponse validateCheckWebAuthn(String user, String transactionId, String webAuthnSignResponse, String origin, Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>();
        // Standard validateCheck data
        params.put(USER, user);
        params.put(TRANSACTION_ID, transactionId);
        params.put(PASS, "");
        appendRealm(params);

        // Additional WebAuthn data
        Map<String, String> wanParams = parser.parseWebAuthnSignResponse(webAuthnSignResponse);
        params.putAll(wanParams);

        Map<String, String> hdrs = new LinkedHashMap<>();
        hdrs.put(HEADER_ORIGIN, origin);
        hdrs.putAll(headers);

        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, hdrs, false, POST);
        return this.parser.parseEMResponse(response);
    }

    /**
     * @see edumfa#validateCheckU2F(String, String, String, Map)
     */
    public EMResponse validateCheckU2F(String user, String transactionId, String signResponse)
    {
        return this.validateCheckU2F(user, transactionId, signResponse, Collections.emptyMap());
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a U2F token.
     *
     * @param user            username
     * @param transactionId   transactionId
     * @param u2fSignResponse the U2F Sign Response as returned from the browser
     * @return EMResponse or null if error
     */
    public EMResponse validateCheckU2F(String user, String transactionId, String u2fSignResponse, Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>();
        // Standard validateCheck data
        params.put(USER, user);
        params.put(TRANSACTION_ID, transactionId);
        params.put(PASS, "");
        appendRealm(params);

        // Additional U2F data
        Map<String, String> u2fParams = parser.parseU2FSignResponse(u2fSignResponse);
        params.putAll(u2fParams);

        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, headers, false, POST);
        return this.parser.parseEMResponse(response);
    }

    /**
     * @see edumfa#triggerChallenges(String, Map)
     */
    public EMResponse triggerChallenges(String username)
    {
        return this.triggerChallenges(username, new LinkedHashMap<>());
    }

    /**
     * Trigger all challenges for the given username. This requires a service account to be set.
     *
     * @param username username to trigger challenges for
     * @param headers  optional headers for the request
     * @return the server response or null if error
     */
    public EMResponse triggerChallenges(String username, Map<String, String> headers)
    {
        Objects.requireNonNull(username, "Username is required!");

        if (!serviceAccountAvailable())
        {
            log("No service account configured. Cannot trigger challenges");
            return null;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        appendRealm(params);

        String response = runRequestAsync(ENDPOINT_TRIGGERCHALLENGE, params, headers, true, POST);
        return this.parser.parseEMResponse(response);
    }

    /**
     * Poll for status of the given transaction ID once.
     *
     * @param transactionId transaction ID to poll for
     * @return the status value, true or false
     */
    public boolean pollTransaction(String transactionId)
    {
        Objects.requireNonNull(transactionId, "TransactionID is required!");

        String response = runRequestAsync(ENDPOINT_POLLTRANSACTION, Collections.singletonMap(TRANSACTION_ID, transactionId), Collections.emptyMap(),
                                          false, GET);
        EMResponse EMResponse = this.parser.parseEMResponse(response);
        return EMResponse.value;
    }

    /**
     * Get the auth token from the /auth endpoint using the service account.
     *
     * @return auth token or null.
     */
    public String getAuthToken()
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot retrieve auth token without service account!");
            return null;
        }
        String response = runRequestAsync(ENDPOINT_AUTH, serviceAccountParam(), Collections.emptyMap(), false, POST);
        return parser.extractAuthToken(response);
    }

    Map<String, String> serviceAccountParam()
    {
        Map<String, String> authTokenParams = new LinkedHashMap<>();
        authTokenParams.put(USERNAME, configuration.serviceAccountName);
        authTokenParams.put(PASSWORD, configuration.serviceAccountPass);

        if (configuration.serviceAccountRealm != null && !configuration.serviceAccountRealm.isEmpty())
        {
            authTokenParams.put(REALM, configuration.serviceAccountRealm);
        }
        else if (configuration.realm != null && !configuration.realm.isEmpty())
        {
            authTokenParams.put(REALM, configuration.realm);
        }
        return authTokenParams;
    }

    /**
     * Retrieve information about the users tokens. This requires a service account to be set.
     *
     * @param username username to get info for
     * @return possibly empty list of TokenInfo or null if failure
     */
    public List<TokenInfo> getTokenInfo(String username)
    {
        Objects.requireNonNull(username);
        if (!serviceAccountAvailable())
        {
            error("Cannot retrieve token info without service account!");
            return null;
        }

        String response = runRequestAsync(ENDPOINT_TOKEN, Collections.singletonMap(USER, username), new LinkedHashMap<>(), true, GET);
        return parser.parseTokenInfoList(response);
    }

    /**
     * Enroll a new token of the specified type for the specified user.
     * This requires a service account to be set. Currently, only HOTP and TOTP type token are supported.
     *
     * @param username     username
     * @param typeToEnroll token type to enroll
     * @return RolloutInfo which contains all info for the token or null if error
     */
    public RolloutInfo tokenRollout(String username, String typeToEnroll)
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        params.put(TYPE, typeToEnroll);
        params.put(GENKEY, "1"); // Let the server generate the secret

        String response = runRequestAsync(ENDPOINT_TOKEN_INIT, params, new LinkedHashMap<>(), true, POST);

        return parser.parseRolloutInfo(response);
    }

    /**
     * Init a new token of the specified type for the specified user.
     * This requires a service account to be set. Currently, only HOTP and TOTP type token are supported.
     *
     * @param username     username
     * @param typeToEnroll token type to enroll
     * @param otpKey       secret to import
     * @return RolloutInfo which contains all info for the token or null if error
     */
    public RolloutInfo tokenInit(String username, String typeToEnroll, String otpKey)
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        params.put(TYPE, typeToEnroll);
        params.put(OTPKEY, otpKey); // Import the secret

        String response = runRequestAsync(ENDPOINT_TOKEN_INIT, params, new LinkedHashMap<>(), true, POST);

        return parser.parseRolloutInfo(response);
    }

    private void appendRealm(Map<String, String> params)
    {
        if (configuration.realm != null && !configuration.realm.isEmpty())
        {
            params.put(REALM, configuration.realm);
        }
    }

    /**
     * Run a request in a thread of the thread pool. Then join that thread to the one that was calling this method.
     * If the server takes longer to answer a request, the other requests do not have to wait.
     *
     * @param path              path to the endpoint of the edumfa server
     * @param params            request parameters
     * @param headers           request headers
     * @param authTokenRequired whether an auth token should be acquired prior to the request
     * @param method            http request method
     * @return response of the server as string or null
     */
    private String runRequestAsync(String path, Map<String, String> params, Map<String, String> headers, boolean authTokenRequired, String method)
    {
        Callable<String> callable = new AsyncRequestCallable(this, endpoint, path, params, headers, authTokenRequired, method);
        Future<String> future = threadPool.submit(callable);
        String response = null;
        try
        {
            response = future.get();
        }
        catch (InterruptedException | ExecutionException e)
        {
            log("runRequestAsync: " + e.getLocalizedMessage());
        }
        return response;
    }

    /**
     * @return list of endpoints for which the response is not printed
     */
    public List<String> logExcludedEndpoints()
    {
        return this.logExcludedEndpoints;
    }

    /**
     * @param list list of endpoints for which the response should not be printed
     */
    public void logExcludedEndpoints(List<String> list)
    {
        this.logExcludedEndpoints = list;
    }

    public boolean serviceAccountAvailable()
    {
        return configuration.serviceAccountName != null && !configuration.serviceAccountName.isEmpty() && configuration.serviceAccountPass != null &&
               !configuration.serviceAccountPass.isEmpty();
    }

    EMConfig configuration()
    {
        return configuration;
    }

    /**
     * Pass the message to the appropriate logger implementation.
     *
     * @param message message to log.
     */
    void error(String message)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.error(message);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.pilog(message);
            }
            else
            {
                System.err.println(message);
            }
        }
    }

    /**
     * Pass the error to the appropriate logger implementation.
     *
     * @param e error to log.
     */
    void error(Throwable e)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.error(e);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.pilog(e.getMessage());
            }
            else
            {
                System.err.println(e.getLocalizedMessage());
            }
        }
    }

    /**
     * Pass the message to the appropriate logger implementation.
     *
     * @param message message to log.
     */
    void log(String message)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.log(message);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.pilog(message);
            }
            else
            {
                System.out.println(message);
            }
        }
    }

    /**
     * Pass the error to the appropriate logger implementation.
     *
     * @param e error to log.
     */
    void log(Throwable e)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.log(e);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.pilog(e.getMessage());
            }
            else
            {
                System.out.println(e.getLocalizedMessage());
            }
        }
    }

    @Override
    public void close() throws IOException
    {
        this.threadPool.shutdown();
    }

    /**
     * Get a new Builder to create a edumfa instance.
     *
     * @param serverURL url of the edumfa server.
     * @param userAgent userAgent of the plugin using the java-client.
     * @return Builder
     */
    public static Builder newBuilder(String serverURL, String userAgent)
    {
        return new Builder(serverURL, userAgent);
    }

    public static class Builder
    {
        private final String serverURL;
        private final String userAgent;
        private String realm = "";
        private boolean doSSLVerify = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private String serviceAccountRealm = "";
        private IPILogger logger = null;
        private boolean disableLog = false;
        private IPISimpleLogger simpleLogBridge = null;
        private int httpTimeoutMs = 30000;

        /**
         * @param serverURL the server URL is mandatory to communicate with edumfa.
         * @param userAgent the user agent that should be used in the http requests. Should refer to the plugin, something like "edumfa-Keycloak"
         */
        private Builder(String serverURL, String userAgent)
        {
            this.userAgent = userAgent;
            this.serverURL = serverURL;
        }

        /**
         * Set a logger, which will receive log and error/throwable messages to be passed to the plugins log/error output.
         * This implementation takes precedence over the IPISimpleLogger if both are set.
         *
         * @param logger ILoggerBridge implementation
         * @return Builder
         */
        public Builder logger(IPILogger logger)
        {
            this.logger = logger;
            return this;
        }

        /**
         * Set a simpler logger implementation, which logs all messages as Strings.
         * The IPILogger takes precedence over this if both are set.
         *
         * @param simpleLog IPISimpleLogger implementation
         * @return Builder
         */
        public Builder simpleLogger(IPISimpleLogger simpleLog)
        {
            this.simpleLogBridge = simpleLog;
            return this;
        }

        /**
         * Set a realm that is appended to every request
         *
         * @param realm realm
         * @return Builder
         */
        public Builder realm(String realm)
        {
            this.realm = realm;
            return this;
        }

        /**
         * Set whether to verify the peer when connecting.
         * It is not recommended to set this to false in productive environments.
         *
         * @param sslVerify boolean
         * @return Builder
         */
        public Builder sslVerify(boolean sslVerify)
        {
            this.doSSLVerify = sslVerify;
            return this;
        }

        /**
         * Set a service account, which can be used to trigger challenges etc.
         *
         * @param serviceAccountName account name
         * @param serviceAccountPass account password
         * @return Builder
         */
        public Builder serviceAccount(String serviceAccountName, String serviceAccountPass)
        {
            this.serviceAccountName = serviceAccountName;
            this.serviceAccountPass = serviceAccountPass;
            return this;
        }

        /**
         * Set the realm for the service account if the account is found in a separate realm from the realm set in {@link Builder#realm(String)}.
         *
         * @param serviceAccountRealm realm of the service account
         * @return Builder
         */
        public Builder serviceRealm(String serviceAccountRealm)
        {
            this.serviceAccountRealm = serviceAccountRealm;
            return this;
        }

        /**
         * Disable logging completely regardless of any set loggers.
         *
         * @return Builder
         */
        public Builder disableLog()
        {
            this.disableLog = true;
            return this;
        }

        /**
         * Set the timeout for http requests in milliseconds.
         * @param httpTimeoutMs timeout in milliseconds
         * @return Builder
         */
        public Builder httpTimeoutMs(int httpTimeoutMs)
        {
            this.httpTimeoutMs = httpTimeoutMs;
            return this;
        }

        public EduMFA build()
        {
            EMConfig configuration = new EMConfig(serverURL, userAgent);
            configuration.realm = realm;
            configuration.doSSLVerify = doSSLVerify;
            configuration.serviceAccountName = serviceAccountName;
            configuration.serviceAccountPass = serviceAccountPass;
            configuration.serviceAccountRealm = serviceAccountRealm;
            configuration.disableLog = disableLog;
            configuration.httpTimeoutMs = httpTimeoutMs;
            return new EduMFA(configuration, logger, simpleLogBridge);
        }
    }
}
