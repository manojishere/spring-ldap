package com.ldapauthdemo.springbootLDAPauthenticationapp.security;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{	
	private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
	
	@Value("${ui.ldap.groupSearchBase}")
	private String groupSearchBase;
	@Value("${ui.ldap.role.name}")
	private String groupName;
	@Value("${ui.ldap.providerUrl}")
	private String ldapProviderUrl;
	@Value("${ui.ldap.userDn}")
	private String userDn;
	@Value("${ui.ldap.password}")
	private String password;
	@Value("${ui.ldap.userSearchBase}")
	private String userSearchBase;
	@Value("${ui.ldap.userSearchFilter}")
	private String userSearchFilter;	
	
	  @Override
	  protected void configure(HttpSecurity http) throws Exception {
		  System.out.println("inside configure");
		  /*
	    http
	      .authorizeRequests()
	        .anyRequest().fullyAuthenticated()
	        .and()
	      .formLogin();
	      */

		    http
		      .authorizeRequests()
		      .antMatchers("/swipe-reload").permitAll();
		    
		    http
		      .authorizeRequests()
		        .anyRequest().fullyAuthenticated()
		        .and()
		      .formLogin();
		  
		  /*
		    http.authorizeRequests()
		    .antMatchers("/swipe-reload").permitAll()
	        .antMatchers("/").fullyAuthenticated()
	        .and()
	            .formLogin().loginPage("/login").failureUrl("/login?error")
	                .usernameParameter("username").passwordParameter("password")
	        .and()
	            .logout().logoutSuccessUrl("/login?logout")
	        .and()
	            .exceptionHandling().accessDeniedPage("/403")
	        .and()
	            .csrf();
	            */	  
	  }
	  
	 /*
	  @Override
	  public void configure(AuthenticationManagerBuilder auth) throws Exception {
		  System.out.println("inside configure2");
		    auth
		      .ldapAuthentication()
		        .userDnPatterns("uid={0},ou=people")
		        .groupSearchBase("ou=groups")
		        .contextSource()
		          .url("ldap://localhost:8389/dc=springframework,dc=org")
		          .and()
		        .passwordCompare()
		          .passwordEncoder(new BCryptPasswordEncoder())
		          .passwordAttribute("userPassword");
		  }
		  */
	  
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(ldapAuthenticationProvider());
		}

		@Bean
		public AuthenticationProvider ldapAuthenticationProvider() {
			LdapAuthenticationProvider ldapAuthenticationProvider = null;
			try {
				DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldapProviderUrl);
				contextSource.setUserDn(userDn);
				contextSource.setPassword(password);
				contextSource.afterPropertiesSet();
				LdapUserSearch ldapUserSearch = new FilterBasedLdapUserSearch(userSearchBase, userSearchFilter,
						contextSource);
				BindAuthenticator bindAuthenticator = new BindAuthenticator(contextSource);
				bindAuthenticator.setUserSearch(ldapUserSearch);
				ldapAuthenticationProvider = new LdapAuthenticationProvider(bindAuthenticator,
						ldapAuthoritiesPopulator(contextSource));

			} catch (Exception e) {
				log.error("Exception occured : ", e);
			}
			return ldapAuthenticationProvider;
		}

		@Bean
		public LdapAuthoritiesPopulator ldapAuthoritiesPopulator(DefaultSpringSecurityContextSource contextSource) {

			DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource,
					groupSearchBase) {
				
				private Set<String> groupSet = initGroupSet();
						
				private Set<String> initGroupSet() {
					Set<String> ret =  new HashSet<String>();
					String[] lowGroups = StringUtils.split(StringUtils.lowerCase(groupName),",");
					for(String g: lowGroups) {
						ret.add("role_"+ g);
					}
					return ret;
				}

				@Override
				public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
					Set<GrantedAuthority> groupMembershipRoles = super.getGroupMembershipRoles(userDn, username);
					boolean isMemberOfSpecificAdGroup = false;
					for (GrantedAuthority grantedAuthority : groupMembershipRoles) {
						log.info(String.valueOf(grantedAuthority));
						if (groupSet.contains(StringUtils.lowerCase(grantedAuthority.toString()))) {
							isMemberOfSpecificAdGroup = true;
							break;
						}
					}
					if (!isMemberOfSpecificAdGroup) {
						log.info("User doesn't have access");
						throw new BadCredentialsException("User must be a member of " + groupName);
					}
					return groupMembershipRoles;
				}
			};

			return ldapAuthoritiesPopulator;
		}
	  
	    

}
