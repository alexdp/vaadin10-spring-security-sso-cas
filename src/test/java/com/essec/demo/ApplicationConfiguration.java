package com.essec.demo;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

import com.essec.vaadin10ext.EnableVaadinExtension;


@EnableVaadinExtension
public class ApplicationConfiguration extends SpringBootServletInitializer {

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
		return builder.sources(ApplicationConfiguration.class);
	}

}
