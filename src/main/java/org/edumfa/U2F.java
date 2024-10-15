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

public class U2F extends Challenge
{
    private final String signRequest;

    public U2F(String serial, String message, String client_mode, String image, String transaction_id, String signRequest)
    {
        super(serial, message, client_mode, image, transaction_id, EMConstants.TOKEN_TYPE_U2F);
        this.signRequest = signRequest;
    }

    /**
     * Returns the U2FSignRequest in JSON format as a string, ready to use with pi-u2f.js.
     * If this returns an empty string, it *might* indicate that the PIN of this token should be changed.
     *
     * @return sign request or empty string
     */
    public String signRequest()
    {
        return signRequest;
    }
}
