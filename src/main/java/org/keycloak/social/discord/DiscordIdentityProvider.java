/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.social.discord;

import com.fasterxml.jackson.databind.JsonNode;
import discord4j.core.*;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.*;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;



import java.util.Set;

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class DiscordIdentityProvider extends AbstractOAuth2IdentityProvider<DiscordIdentityProviderConfig>
        implements SocialIdentityProvider<DiscordIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(DiscordIdentityProvider.class);

    public static final String AUTH_URL = "https://discord.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://discord.com/api/oauth2/token";
    public static final String PROFILE_URL = "https://discord.com/api/users/@me";
    public static final String GROUP_URL = "https://discord.com/api/users/@me/guilds";
    public static final String DEFAULT_SCOPE = "openid";
    public static final String GUILDS_SCOPE = "guilds";

    public DiscordIdentityProvider(KeycloakSession session, DiscordIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;

    }
    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String id = getJsonProperty(profile,"id");
        String username = getJsonProperty(profile,"username");
        String email = getJsonProperty(profile,"email");
        BrokeredIdentityContext user = new BrokeredIdentityContext(username,getConfig());
        RealmModel realm = session.realms().getRealmByName("auth");

       //var idsp = realm.getIdentityProviderByAlias("discord");

        //session.users().getUserByFederatedIdentity(realm,new FederatedIdentityModel("discord",id,username));
       // this.retrieveToken(session,new FederatedIdentityModel())
        if (!session.users().searchForUserByUserAttributeStream(realm,"discord_id",id).toList().isEmpty()) {
            user = new BrokeredIdentityContext(session.users().searchForUserByUserAttributeStream(realm,"discord_id",id).toList().get(0).getId(),getConfig());
        } else {
            if (session.users().getUserByFederatedIdentity(realm,new FederatedIdentityModel("discord",id,username)) == null) {
                  log.log(Logger.Level.WARN,"new ErrorPageException(session, Response.Status.UNAUTHORIZED, Messages.INVALID_USER);");
//                throw new AuthenticationFlowException("There is no account registered with the given Discord User!", AuthenticationFlowError.UNKNOWN_USER);
//                throw new IdentityBrokerException("There is no account registered with the given Discord User!");
//                user.setId(username);
//                user.setUsername(username);
//                user.setEmail(email);
//                user.addMapperGrantedRole("discord_linked");
            }
//            else {
//                throw new IdentityBrokerException("There is no account registered with the given Discord userUser!");
//
//                //user = new BrokeredIdentityContext(session.users().getUserByEmail(realm, email).getId(), getConfig());
//               // user.addMapperGrantedRole("discord_linked");
//            }
        }
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        log.debug("doGetFederatedIdentity()");
        JsonNode profile = null;
        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from discord.", e);
        }

        if (getConfig().hasAllowedGuilds()) {
            if (!isAllowedGuild(accessToken)) {
                throw new ErrorPageException(session, Response.Status.FORBIDDEN, Messages.INVALID_REQUESTER);
            }
        }
        return extractIdentityFromProfile(null, profile);
    }

    protected boolean isAllowedGuild(String accessToken) {
        try {
            JsonNode guilds = SimpleHttp.doGet(GROUP_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
            Set<String> allowedGuilds = getConfig().getAllowedGuildsAsSet();
            for (JsonNode guild : guilds) {
                String guildId = getJsonProperty(guild, "id");
                if (allowedGuilds.contains(guildId)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain guilds the current user is a member of from discord.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        if (getConfig().hasAllowedGuilds()) {
            return getConfig().getScopes() + " " + GUILDS_SCOPE;
        } else {
            return getConfig().getScopes();
        }
    }
}
