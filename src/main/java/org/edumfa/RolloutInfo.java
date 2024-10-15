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

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class RolloutInfo
{
    public GoogleURL googleurl = new GoogleURL();
    public OATHURL oathurl = new OATHURL();
    public OTPKey otpkey = new OTPKey();
    public String raw = "";
    public String serial = "";
    public String rolloutState = "";

    public EMError error = null;

    public static class GoogleURL
    {
        public String description = "", img = "", value = "";
    }

    public static class OATHURL
    {
        public String description = "", img = "", value = "";
    }

    public static class OTPKey
    {
        public String description = "", img = "", value = "", value_b32 = "";
    }
}
