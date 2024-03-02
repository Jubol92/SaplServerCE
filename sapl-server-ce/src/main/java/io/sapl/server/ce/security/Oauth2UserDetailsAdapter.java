package io.sapl.server.ce.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class Oauth2UserDetailsAdapter implements OAuth2User, UserDetails {

    private final OAuth2User oauth2User;

    public Oauth2UserDetailsAdapter(OAuth2User oauth2User) {
        this.oauth2User = oauth2User;
    }

    // Implementieren Sie alle erforderlichen Methoden von UserDetails und
    // OAuth2User,
    // indem Sie die Anrufe an oauth2User delegieren

    @Override
    public Map<String, Object> getAttributes() {
        return oauth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oauth2User.getAuthorities();
    }

    @Override
    public String getName() {
        return oauth2User.getName(); // oder ein anderer eindeutiger Bezeichner
    }

    // UserDetails-spezifische Methoden
    @Override
    public String getPassword() {
        return null; // OAuth2User hat typischerweise kein Passwort
    }

    @Override
    public String getUsername() {
        return getName(); // Verwenden Sie den Namen oder einen anderen eindeutigen Bezeichner
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Oder eine spezifische Logik
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Oder eine spezifische Logik
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Oder eine spezifische Logik
    }

    @Override
    public boolean isEnabled() {
        return true; // Oder eine spezifische Logik
    }
}
