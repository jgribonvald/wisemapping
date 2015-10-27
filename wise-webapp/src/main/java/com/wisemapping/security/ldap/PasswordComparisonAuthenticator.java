package com.wisemapping.security.ldap;

/**
 * Created by jgribonvald on 27/10/15.
 */
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.util.Assert;

import java.util.Iterator;

public final class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {
    private static final Log logger = LogFactory.getLog(PasswordComparisonAuthenticator.class);
    private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder();
    private String passwordAttributeName = "userPassword";

    public PasswordComparisonAuthenticator(BaseLdapPathContextSource contextSource) {
        super(contextSource);
    }

    public DirContextOperations authenticate(Authentication authentication) {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, "Can only process UsernamePasswordAuthenticationToken objects");
        DirContextOperations user = null;
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();
        SpringSecurityLdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(this.getContextSource());
        Iterator encodedPassword = this.getUserDns(username).iterator();

        while(encodedPassword.hasNext()) {
            String passwordBytes = (String)encodedPassword.next();

            try {
                user = ldapTemplate.retrieveEntry(passwordBytes, this.getUserAttributes());
            } catch (NameNotFoundException var9) {
                ;
            }

            if(user != null) {
                break;
            }
        }

        if(user == null && this.getUserSearch() != null) {
            user = this.getUserSearch().searchForUser(username);
        }

        if(user == null) {
            throw new UsernameNotFoundException("User not found: " + username, username);
        } else {
            if(logger.isDebugEnabled()) {
                logger.debug("Performing LDAP compare of password attribute \'" + this.passwordAttributeName + "\' for user \'" + user.getDn() + "\'");
            }

            if (user.attributeExists(this.passwordAttributeName)) {
                if (!this.passwordEncoder.isPasswordValid(new String((byte[])user.getObjectAttribute(this.passwordAttributeName)), password, null)) {
                    throw new BadCredentialsException(this.messages.getMessage("PasswordComparisonAuthenticator.badCredentials", "Bad credentials"));
                } else {
                    return user;
                }
            } else {
                throw new IllegalArgumentException("Unsupported password attribute \'" + this.passwordAttributeName + "\'");
            }
        }
    }

    public void setPasswordAttributeName(String passwordAttribute) {
        Assert.hasLength(passwordAttribute, "passwordAttributeName must not be empty or null");
        this.passwordAttributeName = passwordAttribute;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder must not be null.");
        this.passwordEncoder = passwordEncoder;
    }
}

