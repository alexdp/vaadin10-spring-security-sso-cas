package com.essec.vaadin10ext.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.GenericFilterBean;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	public static final String DEFAULT_ROLE = "USER_ROLE";
	private static final String SPRING_SECURITY_PATH = "/j_spring_cas_security_check";
	
	@Value("${cas.server.base-url}")
	private String casBaseUrl;

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("parametrized_by_servicePropertiesConfigurationFilter");
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(authenticationUserDetailsService());
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas30ServiceTicketValidator());
        casAuthenticationProvider.setKey("an_id_for_this_auth_provider_only");
        return casAuthenticationProvider;
    }

    @Bean
	public AuthenticationUserDetailsService authenticationUserDetailsService() {
		AuthenticationUserDetailsService casAuthenticationUserDetailsService = new AuthenticationUserDetailsService() { 
		    @Override
		    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
		        CasAssertionAuthenticationToken casAssertionAuthenticationToken = (CasAssertionAuthenticationToken) authentication;
		        AttributePrincipal principal = casAssertionAuthenticationToken.getAssertion().getPrincipal();
		        String user = principal.getName();
				Map<?, ?> attributes = principal.getAttributes();
				VaadinUser authenticatedUser = new VaadinUser();
				authenticatedUser.setBid(user);
				authenticatedUser.setFirstName((String) attributes.get("givenName"));
				authenticatedUser.setLastName((String) attributes.get("username"));
				authenticatedUser.setMail(user.toLowerCase() + "@essec.edu");
				if (attributes.containsKey("roles")) {
					Object rolesAsObject = attributes.get("roles");
					boolean isOnlyOneRole = String.class.isInstance(rolesAsObject);
					if (isOnlyOneRole) {
						ArrayList<String> roles = new ArrayList<String>();
						roles.add(DEFAULT_ROLE);
						roles.add((String) rolesAsObject);
						authenticatedUser.setRoles(roles);
					}
					if (!isOnlyOneRole) {
						ArrayList<String> roles = new ArrayList<>((List<String>) rolesAsObject);
						roles.add(DEFAULT_ROLE);
						authenticatedUser.setRoles(roles);
					}
				}
		        return authenticatedUser;
		    }
		};
		return casAuthenticationUserDetailsService;
	}

    @Bean
    public Cas30ServiceTicketValidator cas30ServiceTicketValidator() {
        return new Cas30ServiceTicketValidator(this.casBaseUrl);
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setFilterProcessesUrl(SPRING_SECURITY_PATH);
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        return casAuthenticationFilter;
    }

    public GenericFilterBean servicePropertiesConfigurationFilter() {
    	return new GenericFilterBean() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
				String baseURL = getBaseUrl((HttpServletRequest) request);
				serviceProperties().setService(baseURL + SPRING_SECURITY_PATH);
				chain.doFilter(request, response);
			}
			private String getBaseUrl(HttpServletRequest request) {
				String baseUrl = request.getRequestURL().substring(0, request.getRequestURL().length() - request.getRequestURI().length()) + request.getContextPath();
				return baseUrl;
			}
		};
    }
    
    
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(this.casBaseUrl + "/login");
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	// Not using Spring CSRF here to be able to use plain HTML for the login page
    	http.csrf().disable();
    	// Register our SecurityRequestCache, that saves unauthorized access attempts, so
    	// the user is redirected after login.
    	http.requestCache().requestCache(new SecurityRequestCache());
    	// Let go Vaadin internal request
    	http.authorizeRequests().requestMatchers(SecurityUtils::isFrameworkInternalRequest).permitAll();
    	// Check required roles for other requests
    	http.authorizeRequests().anyRequest().hasAnyAuthority(DEFAULT_ROLE);
    	// Retreive callback from cas server
    	http.addFilter(casAuthenticationFilter());
    	// Autoconfogire service url
    	http.addFilterBefore(servicePropertiesConfigurationFilter(), CasAuthenticationFilter.class);
    	// Redirect to login page
        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(casAuthenticationProvider());
    }
    
    /**
	 * Allows access to static resources, bypassing Spring security.
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers(
				// Vaadin Flow static resources
				"/VAADIN/**",

				// the standard favicon URI
				"/favicon.ico",

				// web application manifest
				"/manifest.json", "/sw.js", "/offline-page.html",

				// icons and images
				"/icons/**", "/images/**",

				// (development mode) static resources
				"/frontend/**",

				// (development mode) webjars
				"/webjars/**",

				// (development mode) H2 debugging console
				"/h2-console/**",

				// (production mode) static resources
				"/frontend-es5/**", "/frontend-es6/**");
	}
}
