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

import java.util.ArrayList;
import java.util.List;

public class Challenge
{
    private final List<String> attributes = new ArrayList<>();
    private final String serial;
    private final String clientMode;
    private final String message;
    private final String transactionId;
    private final String type;
    private final String image;

    public Challenge(String serial, String message, String clientMode, String image, String transactionId, String type)
    {
        this.serial = serial;
        this.message = message;
        this.clientMode = clientMode;
        this.image = image;
        this.transactionId = transactionId;
        this.type = type;
    }

    public List<String> getAttributes() {return attributes;}

    public String getSerial() {return serial;}

    public String getMessage() {return message;}

    public String getClientMode() {return clientMode;}

    public String getImage() {return image.replaceAll("\"", "");}

    public String getTransactionID() {return transactionId;}

    public String getType() {return type;}
}
