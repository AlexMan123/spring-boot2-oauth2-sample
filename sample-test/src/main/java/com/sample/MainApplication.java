package com.sample;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.sample.util.LoggingInterceptor;

import springfox.documentation.builders.OAuthBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.GrantType;
import springfox.documentation.service.ImplicitGrant;
import springfox.documentation.service.LoginEndpoint;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger.web.SecurityConfigurationBuilder;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@EnableSwagger2
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RestController
public class MainApplication /*extends WebMvcConfigurerAdapter*/
{

    public static void main(String[] args)
    {
        SpringApplication.run(MainApplication.class, args);
    }
    
    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }
   
    @Bean
    SecurityConfiguration security() {
      return SecurityConfigurationBuilder.builder()//<19>
          .clientId("test-app-client-id")
          .build();
    }
    
    @Bean
    SecurityScheme oauth() {
    	  List<GrantType> grantTypes = new ArrayList<>();
          ImplicitGrant implicitGrant = new ImplicitGrant(new LoginEndpoint("http://localhost:8080/oauth/authorize"),"access_code");
          grantTypes.add(implicitGrant);
          List<AuthorizationScope> scopes = new ArrayList<>();
          scopes.add(new AuthorizationScope("read","Read access on the API"));
        return new OAuthBuilder()
                .name("SECURITY_SCHEME_OAUTH2")
                .grantTypes(grantTypes)
                .scopes(scopes)
                .build();
    }

    @Bean
    public Docket docket()
    {
        return new Docket(DocumentationType.SWAGGER_2)
            .select()
            .apis(RequestHandlerSelectors.basePackage(getClass().getPackage().getName()))
            .paths(PathSelectors.any())
            .build()
            .securitySchemes(Collections.singletonList(oauth()))
            .apiInfo(generateApiInfo());
    }


    private ApiInfo generateApiInfo()
    {
        return new ApiInfo("Sample Service", "This service is to check Sample Service.", "Version 1.0",
            "Sample Service", "123@test.com", "Apache 2.0", "http://www.apache.org/licenses/LICENSE-2.0");
    }
}
