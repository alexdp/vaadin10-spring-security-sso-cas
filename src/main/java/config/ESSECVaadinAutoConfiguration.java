package config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import com.essec.vaadin10ext.EnableVaadinExtension;
import com.essec.vaadin10ext.security.SecurityConfiguration;

@Configuration
@Import(SecurityConfiguration.class)
@ComponentScan(basePackageClasses={EnableVaadinExtension.class})
public class ESSECVaadinAutoConfiguration {

	/**
	 * Needed for injection with @Value annotation
	 * 
	 * @return c
	 */
	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		PropertySourcesPlaceholderConfigurer c = new PropertySourcesPlaceholderConfigurer();
		c.setIgnoreUnresolvablePlaceholders(true);
		return c;
	}
	
   

}
