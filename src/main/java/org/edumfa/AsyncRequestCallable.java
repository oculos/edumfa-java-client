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
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import static org.edumfa.EMConstants.ENDPOINT_AUTH;

/**
 * Instances of this class are submitted to the thread pool so that requests can be executed in parallel.
 */
public class AsyncRequestCallable implements Callable<String>, Callback
{
    private String path;
    private final String method;
    private final Map<String, String> headers;
    private final Map<String, String> params;
    private final boolean authTokenRequired;
    private final Endpoint endpoint;
    private final EduMFA eduMFA;
    final String[] callbackResult = {null};
    private CountDownLatch latch;

    public AsyncRequestCallable(EduMFA eduMFA, Endpoint endpoint, String path, Map<String, String> params,
                                Map<String, String> headers, boolean authTokenRequired, String method)
    {
        this.eduMFA = eduMFA;
        this.endpoint = endpoint;
        this.path = path;
        this.params = params;
        this.headers = headers;
        this.authTokenRequired = authTokenRequired;
        this.method = method;
    }

    @Override
    public String call() throws Exception
    {
        // If an auth token is required for the request, get that first then do the actual request
        if (this.authTokenRequired)
        {
            if (!eduMFA.serviceAccountAvailable())
            {
                eduMFA.error("Service account is required to retrieve auth token!");
                return null;
            }
            latch = new CountDownLatch(1);
            String tmpPath = path;
            path = ENDPOINT_AUTH;
            endpoint.sendRequestAsync(ENDPOINT_AUTH, eduMFA.serviceAccountParam(), Collections.emptyMap(), EMConstants.POST, this);
            if (!latch.await(30, TimeUnit.SECONDS))
            {
                eduMFA.error("Latch timed out...");
                return "";
            }
            // Extract the auth token from the response
            String response = callbackResult[0];
            String authToken = eduMFA.parser.extractAuthToken(response);
            if (authToken == null)
            {
                // The parser already logs the error.
                return null;
            }
            // Add the auth token to the header
            headers.put(EMConstants.HEADER_AUTHORIZATION, authToken);
            path = tmpPath;
            callbackResult[0] = null;
        }

        // Do the actual request
        latch = new CountDownLatch(1);
        endpoint.sendRequestAsync(path, params, headers, method, this);
        if (!latch.await(30, TimeUnit.SECONDS))
        {
            eduMFA.error("Latch timed out...");
            return "";
        }
        return callbackResult[0];
    }

    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e)
    {
        eduMFA.error(e);
        latch.countDown();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException
    {
        if (response.body() != null)
        {
            String s = response.body().string();
            if (!eduMFA.logExcludedEndpoints().contains(path) && !ENDPOINT_AUTH.equals(path))
            {
                eduMFA.log(path + ":\n" + eduMFA.parser.formatJson(s));
            }
            callbackResult[0] = s;
        }
        latch.countDown();
    }
}
