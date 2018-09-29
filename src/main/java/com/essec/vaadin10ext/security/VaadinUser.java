package com.essec.vaadin10ext.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


/**
 * Represents a user
 * 
 * @author Alexandre de Pellegrin
 * 
 */
public class VaadinUser implements UserDetails {
	
	private String bid = "";
	
	private String firstName = "";
	
	private String lastName = "";
	
	private Integer pidm = 0;
	
	private String mail = "";

	private List<String> roles = new ArrayList<String>();
	
	private Collection<GrantedAuthority> authorities;

	
	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return getBid();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
	
	public String getBid() {
		return bid;
	}

	public void setBid(String principal) {
		this.bid = principal;
	}

	public String getFullname() {
		String fullname = getFirstName() + " " + getLastName();
		if (StringUtils.isBlank(fullname)) {
			fullname = bid;
		}
		if (StringUtils.isBlank(fullname)) {
			fullname = "";
		}
		return fullname.trim();
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public Integer getPidm() {
		return pidm;
	}

	public void setPidm(Integer pidm) {
		this.pidm = pidm;
	}

	public String getMail() {
		return mail;
	}

	public void setMail(String mail) {
		this.mail = mail;
	}
	
	public List<String> getRoles() {
		List<String> result = new ArrayList<>();
		for (String aRole : roles) {
			String[] splitPath = aRole.split(",");
			if (splitPath.length < 2) {
				result.add(aRole);
				continue;
			}
			for (String element : splitPath) {
				if (element.toLowerCase().contains("cn=")) {
					element = element.replace("cn=", "");
					element = element.replace("CN=", "");
					element = element.trim();
					result.add(element);
				}
			}
		}
		return result;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public boolean isUserInRole(String role) {
		for (String aRole : roles) {
			if (aRole.toLowerCase().contains(role.toLowerCase())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		if (this.authorities == null) {
			this.authorities = new ArrayList<>();
			for (String aRole : getRoles()) {
				this.authorities.add(new SimpleGrantedAuthority(aRole));
			}
		}
		return this.authorities;
	}


}
