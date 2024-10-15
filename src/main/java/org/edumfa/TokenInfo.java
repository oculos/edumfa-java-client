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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class TokenInfo
{
    public boolean active = false;
    public int count = 0;
    public int countWindow = 0;
    public String description = "";
    public int failCount = 0;
    public int id = 0;
    public final Map<String, String> info = new HashMap<>();
    public boolean locked = false;
    public int maxFail = 0;
    public int otpLen = 0;
    public final List<String> realms = new ArrayList<>();
    public String resolver = "";
    public boolean revoked = false;
    public String rolloutState = "";
    public String serial = "";
    public String image = "";
    public int syncWindow = 0;
    public String tokenType = "";
    public boolean userEditable = false;
    public String userID = "";
    public String userRealm = "";
    public String username = "";
    public String rawJson = "";
}
