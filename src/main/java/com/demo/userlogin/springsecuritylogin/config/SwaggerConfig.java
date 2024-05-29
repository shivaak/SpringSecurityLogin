package com.demo.userlogin.springsecuritylogin.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Profile({"dev"})//config only in dev profile
public class SwaggerConfig {

    public SwaggerConfig() {
        log.info("SwaggerConfig loaded because the 'dev' profile is active.");
    }

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Spring boot login service with JWT authentication")
                        .version("1.0")
                        .description("This is a sample Spring Boot Restful application demonstrating JWT authentication.")
                        .contact(new Contact()
                                .name("Shivaa Krishnan")
                                .url("http://linkedin.com/in/shivaak")
                                .email("shivainfotech12@gmail.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("http://springdoc.org")))
                .addTagsItem(new Tag().name("user").description("Operations about users"))
                //.addTagsItem(new Tag().name("user").description("Operations about users"))
                .addServersItem(new Server().url("http://localhost:8080").description("Local server"))
                .addServersItem(new Server().url("https://api.example.com").description("Production server"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
