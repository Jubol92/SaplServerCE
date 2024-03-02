/*
 * Copyright (C) 2017-2024 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.sapl.server.ce.security;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import com.vaadin.flow.spring.security.AuthenticationContext;

import lombok.RequiredArgsConstructor;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class AuthenticatedUser {

    private final AuthenticationContext authenticationContext;

    private boolean isOauth2User = false;

    public Optional<UserDetails> get() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() instanceof OAuth2User) {
            isOauth2User = true;
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            return Optional.of(new Oauth2UserDetailsAdapter(oauth2User));
        } else if (authentication.getPrincipal() instanceof UserDetails) {
            return Optional.of((UserDetails) authentication.getPrincipal());
        }
        return Optional.empty();
    }

    public void logout() {
        if (isOauth2User) {
            System.out.println("LOGOUT FROM KEYCLOAK");
            Authentication       authentication     = SecurityContextHolder.getContext().getAuthentication();
            OidcUser             user               = ((OidcUser) authentication.getPrincipal());
            String               endSessionEndpoint = "http://localhost:9000/realms/SAPL/protocol/openid-connect/logout";
            UriComponentsBuilder builder            = UriComponentsBuilder.fromUriString(endSessionEndpoint)
                    .queryParam("id_token_hint", user.getIdToken().getTokenValue());

            RestTemplate           restTemplate = new RestTemplate();
            ResponseEntity<String> response     = restTemplate.getForEntity(builder.toUriString(), String.class);
            SecurityContextHolder.clearContext();
            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Erfolgreich von Keycloak abgemeldet.");
            } else {
                System.out.println("Fehler beim Abmelden von Keycloak: " + response.getStatusCode());
            }
        } else {
            authenticationContext.logout();
        }
    }

    public boolean getIsOauth2User() {
        return isOauth2User;
    }
}
