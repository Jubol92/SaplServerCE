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

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.*;
import java.util.stream.Collectors;

import io.sapl.server.ce.ui.views.login.LoginView;
import org.checkerframework.checker.units.qual.K;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.oauth2.login.OAuth2LoginSecurityMarker;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import com.vaadin.flow.spring.security.VaadinWebSecurity;

import io.sapl.server.ce.security.apikey.ApiKeaderHeaderAuthFilterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Configuration
@EnableWebSecurity
@OAuth2LoginSecurityMarker
@RequiredArgsConstructor
@KeycloakConfiguration
public class HttpSecurityConfiguration extends VaadinWebSecurity {
    @Value("${io.sapl.server.allowBasicAuth:#{false}}")
    private boolean allowBasicAuth;

    @Value("${io.sapl.server.allowApiKeyAuth:#{true}}")
    private boolean allowApiKeyAuth;

    @Value("${io.sapl.server.allowOauth2Auth:#{false}}")
    private boolean allowOauth2Auth;

    @Value("${io.sapl.server.allowKeycloakLogin:#{true}}")
    private boolean allowKeycloakLogin;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:#{null}}")
    private String jwtIssuerURI;

    private final ApiKeaderHeaderAuthFilterService apiKeyAuthenticationFilterService;

    private final KeycloakLogoutHandler keycloakLogoutHandler = new KeycloakLogoutHandler();
    private static final String         GROUPS                = "groups";
    private static final String         REALM_ACCESS_CLAIM    = "realm_access";
    private static final String         ROLES_CLAIM           = "roles";

    /**
     * Decodes JSON Web Token (JWT) according to the configuration that was
     * initialized by the OpenID Provider specified in the jwtIssuerURI.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        if (allowOauth2Auth) {
            return JwtDecoders.fromIssuerLocation(jwtIssuerURI);
        } else {
            return null;
        }
    }

    /*
     * @Bean JwtAuthenticationConverter jwtAuthenticationConverter() {
     * JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
     * converter.setJwtGrantedAuthoritiesConverter( jwt -> List.of(new
     * SimpleGrantedAuthority(ClientDetailsService.CLIENT))); return converter; }
     */

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 5)
    public SecurityFilterChain apiAuthnFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.securityMatcher("/api/**") // API path
                .csrf(AbstractHttpConfigurer::disable)    // api is not to be browser, disable CSRF token
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // no session required
        http
                .oauth2Login(withDefaults())
                .logout(logout -> logout.addLogoutHandler(keycloakLogoutHandler).logoutSuccessUrl("/").logoutSuccessHandler((request, response, authentication) -> {
                    response.sendRedirect("/oauth2");
        }))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/unauthenticated", "/oauth2/**", "/login/**", "/VAADIN/push/**").permitAll());
        return http.build();
    }

    /**
     * This filter chain is offering Basic Authn for the API.
     *
     * @param http the HttpSecurity.
     * @return configured HttpSecurity
     * @throws Exception if error occurs during HTTP security configuration
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.authorizeHttpRequests(
        http.authorizeHttpRequests(
                requests -> requests.requestMatchers(new AntPathRequestMatcher("/images/*.png")).permitAll());

        // Icons from the line-awesome addon
        http.authorizeHttpRequests(
                requests -> requests.requestMatchers(new AntPathRequestMatcher("/line-awesome/**/*.svg")).permitAll());

        // Xtext services
        http.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/xtext-service/**", "/VAADIN/push")));
        super.configure(http);

        if(allowKeycloakLogin){
            setOAuth2LoginPage(http, "/oauth2");
        }
        else{
            setLoginView(http, LoginView.class);
        }
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.clientRegistration());
    }
    // Bean needed by oauth2Login
    @Bean
    public ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak").clientId("sapl-client")
                .clientSecret("wv2l9NvuSowvr8PwkY8qLKPIDi0HZEHT")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                //.redirectUri("{baseUrl}/empty")
                .scope("openid", "profile", "email", "address", "phone", "roles")
                .issuerUri("http://localhost:9000/realms/SAPL")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("http://localhost:9000/realms/SAPL/protocol/openid-connect/certs") // JWK Set URI hinzugefügt
                .authorizationUri("http://localhost:9000/realms/SAPL/protocol/openid-connect/auth")
                .tokenUri("http://localhost:9000/realms/SAPL/protocol/openid-connect/token")
                .userInfoUri("http://localhost:9000/realms/SAPL/protocol/openid-connect/userinfo")
                .registrationId("keycloak").build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    /*
    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> authorities.stream()
                .map(authority -> {
                    System.out.println("Authority:::: " + authority.getAuthority());
                    if (!authority.getAuthority().startsWith("ROLE_")) {
                        return new SimpleGrantedAuthority("ROLE_" + authority.getAuthority());
                    }
                    return authority;
                })
                .collect(Collectors.toList());
    }
    */

    /*
    @Bean
    @SuppressWarnings("unchecked")
    public GrantedAuthoritiesMapper userAuthoritiesMapperForKeycloak() {
        System.out.println();
        System.out.println("Granted");
        System.out.println("Granted");
        System.out.println("Granted");
        System.out.println();

        return new SimpleAuthorityMapper();
        return authorities -> {
            System.out.println();
            System.out.println("Granted");
            System.out.println("Granted");
            System.out.println("Granted");
            System.out.println();
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            var authority = authorities.iterator().next();
            boolean isOidc = authority instanceof OidcUserAuthority;

            if (isOidc) {
                System.out.println("");
                System.out.println("IF");
                System.out.println("IF");
                System.out.println("IF");
                System.out.println("");
                var oidcUserAuthority = (OidcUserAuthority) authority;
                var userInfo = oidcUserAuthority.getUserInfo();

                if (userInfo.hasClaim(REALM_ACCESS_CLAIM)) {
                    System.out.println(userInfo.getClaimAsMap(REALM_ACCESS_CLAIM));
                    var realmAccess = userInfo.getClaimAsMap(REALM_ACCESS_CLAIM);
                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            } else {
                System.out.println("");
                System.out.println("ELSE");
                System.out.println("ELSE");
                System.out.println("ELSE");
                System.out.println("");

                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                if (userAttributes.containsKey(REALM_ACCESS_CLAIM)) {
                    System.out.println((Map<String, Object>) userAttributes.get(REALM_ACCESS_CLAIM));
                    var realmAccess = (Map<String, Object>) userAttributes.get(REALM_ACCESS_CLAIM);
                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            }
            return mappedAuthorities;
        };
    }
    */

    /*
    Collection<GrantedAuthority> generateAuthoritiesFromClaim(Collection<String> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
    }
     */

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapperForKeycloak() {
        return authorities -> {
            Set mappedAuthorities = new HashSet<>();
            var authority = authorities.iterator().next();
            boolean isOidc = authority instanceof OidcUserAuthority;

            if (isOidc) {
                var oidcUserAuthority = (OidcUserAuthority) authority;
                var userInfo = oidcUserAuthority.getUserInfo();

                // Tokens can be configured to return roles under
                // Groups or REALM ACCESS hence have to check both
                if (userInfo.hasClaim(REALM_ACCESS_CLAIM)) {
                    var realmAccess = userInfo.getClaimAsMap(REALM_ACCESS_CLAIM);
                    var roles = (Collection) realmAccess.get(ROLES_CLAIM);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                } else if (userInfo.hasClaim(GROUPS)) {
                    Collection roles = (Collection) userInfo.getClaim(
                            GROUPS);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            } else {
                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                if (userAttributes.containsKey(REALM_ACCESS_CLAIM)) {
                    Map<String, Object> realmAccess = (Map<String, Object>) userAttributes.get(
                            REALM_ACCESS_CLAIM);
                    Collection roles = (Collection) realmAccess.get(ROLES_CLAIM);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            }
            return mappedAuthorities;
        };
    }

    Collection generateAuthoritiesFromClaim(Collection roles) {
        return (Collection) roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(
                Collectors.toList());
    }
}
