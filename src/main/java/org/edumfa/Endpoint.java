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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;

import static org.edumfa.EMConstants.GET;
import static org.edumfa.EMConstants.HEADER_USER_AGENT;
import static org.edumfa.EMConstants.POST;
import static org.edumfa.EMConstants.WEBAUTHN_PARAMETERS;

/**
 * This class handles sending requests to the server.
 */
class Endpoint
{
    private final EduMFA eduMFA;
    private final EMConfig EMConfig;
    private final OkHttpClient client;

    final TrustManager[] trustAllManager = new TrustManager[]{new X509TrustManager()
    {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
        {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
        {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers()
        {
            return new java.security.cert.X509Certificate[]{};
        }
    }};

    Endpoint(EduMFA eduMFA)
    {
        this.eduMFA = eduMFA;
        this.EMConfig = eduMFA.configuration();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(EMConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               .writeTimeout(EMConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               .readTimeout(EMConfig.httpTimeoutMs, TimeUnit.MILLISECONDS);

        if (!this.EMConfig.doSSLVerify)
        {
            // Trust all certs and verify every host
            try
            {
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllManager, new java.security.SecureRandom());
                final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllManager[0]);
                builder.hostnameVerifier((s, sslSession) -> true);
            }
            catch (KeyManagementException | NoSuchAlgorithmException e)
            {
                eduMFA.error(e);
            }
        }
        this.client = builder.build();
    }

    /**
     * Add a request to the okhttp queue. The callback will be invoked upon success or failure.
     *
     * @param endpoint server endpoint
     * @param params   request parameters
     * @param headers  request headers
     * @param method   http request method
     * @param callback okhttp3 callback
     */
    void sendRequestAsync(String endpoint, Map<String, String> params, Map<String, String> headers, String method,
                          Callback callback)
    {
        HttpUrl httpUrl = HttpUrl.parse(EMConfig.serverURL + endpoint);
        if (httpUrl == null)
        {
            eduMFA.error("Server url could not be parsed: " + (EMConfig.serverURL + endpoint));
            // Invoke the callback to terminate the thread that called this function.
            callback.onFailure(null, new IOException("Request could not be created because the url could not be parsed"));
            return;
        }
        HttpUrl.Builder urlBuilder = httpUrl.newBuilder();
        eduMFA.log(method + " " + endpoint);
        params.forEach((k, v) ->
                       {
                           if (k.equals("pass") || k.equals("password"))
                           {
                               v = "*".repeat(v.length());
                           }

                           eduMFA.log(k + "=" + v);
                       });

        if (GET.equals(method))
        {
            params.forEach((key, value) ->
                           {
                               String encValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
                               urlBuilder.addQueryParameter(key, encValue);
                           });
        }

        String url = urlBuilder.build().toString();
        //eduMFA.log("URL: " + url);
        Request.Builder requestBuilder = new Request.Builder().url(url);

        // Add the headers
        requestBuilder.addHeader(HEADER_USER_AGENT, EMConfig.userAgent);
        if (headers != null && !headers.isEmpty())
        {
            headers.forEach(requestBuilder::addHeader);
        }

        if (POST.equals(method))
        {
            FormBody.Builder formBodyBuilder = new FormBody.Builder();
            params.forEach((key, value) ->
                           {
                               if (key != null && value != null)
                               {
                                   String encValue = value;
                                   // WebAuthn params are excluded from url encoding,
                                   // they are already in the correct encoding for the server
                                   if (!WEBAUTHN_PARAMETERS.contains(key))
                                   {
                                       encValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
                                   }
                                   formBodyBuilder.add(key, encValue);
                               }
                           });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        Request request = requestBuilder.build();
        //eduMFA.log("HEADERS:\n" + request.headers().toString());
        client.newCall(request).enqueue(callback);
    }
}
